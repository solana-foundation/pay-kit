--[[
MPP scheme adapter.

Wraps the existing `mpp.server` module (challenge issuance + credential
verification + settlement orchestration) behind the PayKit dispatcher
contract. The legacy module did the protocol work; this adapter does
the PayKit wiring (operator -> recipient, config -> network/RPC, gate
-> amount/splits, errors -> canonical L6 codes).

Adapter contract (matching the cross-SDK shape used by Ruby):
- detect(headers)             -> bool   does this request carry a MPP envelope
- accepts_entry(gate, req)    -> table  one entry in the 402 `accepts[]`
- challenge_headers(gate, req)-> table  protocol-specific 402 headers
- verify_and_settle(gate, req)-> (payment, err)
                                 payment shape: {protocol="mpp", scheme="charge",
                                 transaction, settlement_headers, raw}

Adapter instances are per-request lightweight wrappers; the underlying
`mpp.server.new(...)` constructor is invoked lazily and cached on the
adapter so repeated calls within a request reuse the inner state. The
dispatcher (P6) owns the across-request cache.
]]

local mpp_server = require('pay_kit.protocols.mpp.server')
local mpp_intents = require('pay_kit.protocols.mpp.charge')
local mpp_protocol = require('pay_kit.solana.mints')
local expires_mod  = require('pay_kit.protocols.mpp.expires')
local error_codes  = require('pay_kit.protocol.core.error_codes')

local M = {}
local Adapter = {}
Adapter.__index = Adapter

-- Emit a one-shot warning when the MPP replay store falls back to the
-- volatile in-memory default. Localnet is exempt (single-worker dev is the
-- expected shape there); mainnet/devnet warn so an operator who forgot to
-- wire a shared store is told at first server build rather than after a
-- cross-worker double-spend.
local _warned_volatile_replay_store = false
local function warn_volatile_replay_store(network)
  if network == 'localnet' then return end
  if _warned_volatile_replay_store then return end
  _warned_volatile_replay_store = true
  local msg = 'pay_kit: MPP replay protection is using the default in-memory ' ..
    'store, which is process-local and lost on restart. On a multi-worker or ' ..
    'multi-node deploy a settled signature can be replayed against another ' ..
    'worker. Supply config.mpp.replay_store with a shared (ngx.shared.dict / ' ..
    'Redis-backed) store in production.'
  local ngx_ref = rawget(_G, 'ngx')
  if ngx_ref and ngx_ref.log and ngx_ref.WARN then
    ngx_ref.log(ngx_ref.WARN, msg)
  else
    io.stderr:write('[pay_kit] WARN: ' .. msg .. '\n')
  end
end

local function map_pay_kit_network(network)
  -- The legacy mpp.server.new accepts "mainnet" / "devnet" / "localnet";
  -- pay_kit config uses solana_* prefixes.
  local mapping = {
    solana_mainnet  = 'mainnet',
    solana_devnet   = 'devnet',
    solana_localnet = 'localnet',
  }
  return mapping[network] or 'localnet'
end

-- Build a per-gate MPP server. The legacy `mpp.server.new(config)`
-- requires a `verify_payment` callback that runs the settlement
-- lifecycle (decode tx, simulate, broadcast, consume signature,
-- confirm). Wire that up from `pay_kit.protocols.mpp.server.charge_handler` so the
-- inner server can settle - without it, mpp.server raises
-- "verify_payment callback is required" at construct time.
local function build_mpp_server(config, gate, store)
  local primary_coin = gate:amount():primary_coin()
  local network = map_pay_kit_network(config.network)
  local fee_payer_signer
  local sgn = config.operator:signer()
  if config.operator:fee_payer() and type(sgn._secret_key_bytes) == 'function' then
    -- Build a legacy mpp signer from the operator's raw bytes so the
    -- charge_handler's pull_transaction_signer hook can cosign.
    local mpp_signer = require('pay_kit.solana.local_signer')
    fee_payer_signer = mpp_signer.from_bytes(sgn:_secret_key_bytes())
  end

  local rpc_mod = require('pay_kit.solana.rpc')
  local rpc_transport_mod = require('pay_kit.solana.rpc_transport')
  local charge_handler = require('pay_kit.protocols.mpp.server.charge_handler')
  local solana_verify  = require('pay_kit.protocols.mpp.server.solana_verify')
  local store_mod      = require('pay_kit.protocols.mpp.store')

  local rpc = rpc_mod.new({url = config.rpc_url, transport = rpc_transport_mod.new()})
  local verifier_bundle = solana_verify.new_real_verifier({pull_signer = fee_payer_signer})
  -- The legacy mpp.store expects (key, value) semantics on
  -- put_if_absent (it stores arbitrary values keyed by signature).
  -- pay_kit.store uses (key, ttl) for the x402 replay path, so
  -- they are NOT interchangeable - bind the mpp handler to its own
  -- store. The `store` argument from the dispatcher is reserved for
  -- the x402 adapter.
  local _ = store
  -- Replay store. The default `store.memory()` is process-local and lost
  -- on worker restart, so it only protects against replays seen by the
  -- SAME worker since boot - acceptable for single-worker dev, NOT for a
  -- multi-worker / multi-node production deploy where a replay reservation
  -- must be visible across all settlers. Callers wire a shared store
  -- (e.g. an ngx.shared.dict / Redis-backed adapter) via
  -- `config.mpp.replay_store`; when none is supplied we fall back to the
  -- volatile in-memory store and warn once so the dev-only nature is
  -- explicit. Mirrors the Ruby/PHP "default volatile replay store" caveat.
  local replay_store = config.mpp and config.mpp.replay_store
  if not replay_store then
    replay_store = store_mod.memory()
    warn_volatile_replay_store(network)
  end
  local handler = charge_handler.new({
    rpc                       = rpc,
    network                   = network,
    replay_store              = replay_store,
    transaction_verifier      = verifier_bundle.transaction_verifier,
    pull_transaction_signer   = verifier_bundle.pull_transaction_signer,
    pull_blockhash_extractor  = verifier_bundle.pull_blockhash_extractor,
  })

  local opts = {
    recipient      = gate:pay_to(),
    currency       = primary_coin,
    decimals       = 6,
    secret_key     = config.mpp.challenge_binding_secret,
    realm          = config.mpp.realm,
    network        = network,
    rpc_url        = config.rpc_url,
    verify_payment = handler:as_callback(),
  }
  if fee_payer_signer then
    opts.fee_payer = true
    opts.fee_payer_key = fee_payer_signer.public_key
  end
  return mpp_server.new(opts)
end

-- Build the MPP splits[] field from a gate's fees. The verifier
-- computes `primary = total - sum(splits)` and matches a transfer of
-- `primary` to `request.recipient`, so splits[] must contain ONLY
-- the fee recipients (verifier-aligned; mirrors the Ruby PR #138
-- fix to the splits primary exclusion).
-- Interop side-channel: allow the harness (or any adapter wiring) to
-- inject the literal splits[] payload (carrying ataCreationRequired,
-- memo, etc.) per gate name. The pay_kit gate model doesn't carry
-- ataCreationRequired natively because it's an MPP wire concern, not
-- a pricing concern.
local SPLITS_OVERRIDE = {}
function M.set_splits_override(gate_name, splits)
  SPLITS_OVERRIDE[gate_name] = splits
end

local function splits_for(gate)
  local override = SPLITS_OVERRIDE[gate:name()]
  if override and #override > 0 then return override end
  if not gate:has_fees() then return nil end
  local out = {}
  for _, fee in ipairs(gate:fees()) do
    out[#out + 1] = {recipient = fee:recipient(), amount = tostring(fee:units())}
  end
  return out
end

-- New adapter. `config_resolver` is a `function() return config end`
-- so the adapter can be built once and re-read the (post-configure)
-- pay_kit config on every request. `store` is the replay-protection
-- backing (resolved by the dispatcher).
function M.new(opts)
  opts = opts or {}
  if not opts.config_resolver then
    return nil, 'pay_kit: protocols.mpp.new requires config_resolver'
  end
  return setmetatable({
    _config_resolver = opts.config_resolver,
    _store           = opts.store,
    _server_cache    = {},
  }, Adapter)
end

local function cache_key(gate, config)
  return table.concat({
    gate:pay_to(),
    gate:amount():primary_coin(),
    config.network,
    config.rpc_url or '',
    config.mpp.realm or '',
    tostring(config.mpp.expires_in),
  }, '|')
end

function Adapter:_server_for(gate)
  local config = self._config_resolver()
  local key = cache_key(gate, config)
  local server = self._server_cache[key]
  if server then return server, config end
  server = build_mpp_server(config, gate, self._store)
  self._server_cache[key] = server
  return server, config
end

-- Detect: does the inbound request carry an MPP Authorization header?
function M.detect(headers)
  if type(headers) ~= 'table' then return false end
  local auth = headers['authorization'] or headers['Authorization']
  if type(auth) ~= 'string' then return false end
  return auth:lower():find('^payment ') ~= nil
end

Adapter.detect = function(_, headers) return M.detect(headers) end

-- Build the 402 body entry for `accepts[]`. The legacy mpp server's
-- `:charge_with_options` returns the wire challenge; we reshape into
-- the cross-SDK adapter contract.
function Adapter:accepts_entry(gate, _req)
  local server, _config = self:_server_for(gate)
  local amount_units = tostring(gate:total_units())
  return {
    protocol     = 'mpp',
    scheme       = 'charge',
    amount       = amount_units,
    currency     = gate:amount():primary_coin(),
    payTo        = gate:pay_to(),
    splits       = splits_for(gate),
    realm        = server.realm,
  }
end

-- Emit the `WWW-Authenticate: Payment` header carrying the signed
-- challenge. Calls into the legacy server's challenge issuance and
-- formats per RFC 9110. mpp.server:charge() takes the HUMAN-decimal
-- amount (e.g. "0.001") and multiplies by 10^decimals internally;
-- the gate.amount's `amount_string()` already carries that form.
function Adapter:challenge_headers(gate, _req)
  local server, config = self:_server_for(gate)
  local display_amount = gate:amount():amount_string()
  local options = {}
  local splits = splits_for(gate)
  if splits then options.splits = splits end
  -- Wire the configured challenge TTL into issuance so signed challenges
  -- are not valid indefinitely. `config.mpp.expires_in` is seconds-from-now
  -- (default 300); `false` is the explicit development opt-out that leaves
  -- the challenge without an expiry. Mirrors PHP/Ruby/Python which seed a
  -- short TTL at challenge construction rather than relying on every caller
  -- to pass one. `verify_credential_with_expected` enforces the expiry via
  -- `challenge_value:is_expired`.
  local expires_in = config.mpp.expires_in
  if type(expires_in) == 'number' and expires_in > 0 then
    options.expires = expires_mod.format_rfc3339(os.time() + expires_in)
  end
  local ok, challenge = pcall(server.charge_with_options, server, display_amount, options)
  if not ok then
    -- Server-side rejection at challenge time (e.g. splits > 8 or
    -- splits sum >= amount). Emit a no-challenge 402 so the caller's
    -- response stays well-formed.
    return {}
  end
  local headers_mod = require('pay_kit.protocol.core.headers')
  return {
    ['www-authenticate'] = headers_mod.format_www_authenticate(challenge),
  }
end

-- Verify a submitted credential. Returns either a `payment` table
-- (success) or `(nil, err)` mapped to the canonical L6 code so the
-- dispatcher can surface body.code on the 402.
function Adapter:verify_and_settle(gate, req)
  local server = self:_server_for(gate)
  local headers = (req and req.headers) or {}
  local authorization = headers['authorization'] or headers['Authorization']
  if not authorization or authorization == '' then
    return nil, 'pay_kit: payment required'
  end

  -- pay_kit.protocol.core.headers parses "Payment <base64>" into a
  -- Credential the inner server consumes. The adapter does this
  -- decode here so the umbrella's dispatcher never touches the
  -- legacy mpp parsing surface directly.
  local headers_mod = require('pay_kit.protocol.core.headers')
  local credential, parse_err = headers_mod.parse_authorization(authorization)
  if not credential then
    return nil, 'pay_kit: invalid proof: ' .. tostring(parse_err)
  end

  -- The route-expected request must carry the FULL on-chain shape the
  -- challenge was issued with, not just amount/currency/recipient.
  -- `verify_credential_with_expected` now binds methodDetails + externalId
  -- (stripping only recentBlockhash) and settles from `expected`, so a
  -- credential issued for a different shape (different splits, fee payer,
  -- or token program) on the same price/recipient is rejected. Reconstruct
  -- the same methodDetails `charge_with_options` builds inside
  -- `build_mpp_server` (network, decimals/tokenProgram for SPL, splits,
  -- feePayer/feePayerKey). Mirrors PHP Adapter::chargeRequestFor and Ruby
  -- Mpp::Server::Charge#charge which both pass the route's full request
  -- into verification.
  local currency = gate:amount():primary_coin()
  local is_native_sol = string.lower(currency or '') == 'sol'
  local expected_method_details = {
    network = server.network,
  }
  if not is_native_sol then
    expected_method_details.decimals = server.decimals
    if mpp_protocol.stablecoin_symbol(currency) then
      expected_method_details.tokenProgram =
        mpp_protocol.default_token_program_for_currency(currency, server.network)
    end
  end
  local expected_splits = splits_for(gate)
  if expected_splits then
    expected_method_details.splits = expected_splits
  end
  if server.fee_payer then
    expected_method_details.feePayer = true
    if server.fee_payer_key then
      expected_method_details.feePayerKey = server.fee_payer_key
    end
  end
  local expected = {
    amount        = tostring(gate:total_units()),
    currency      = currency,
    recipient     = gate:pay_to(),
    methodDetails = expected_method_details,
  }
  local ok, result_or_err = pcall(function()
    return server:verify_credential_with_expected(credential, expected)
  end)
  if not ok then
    -- pay_kit.protocol.core.error_codes.raise throws `{code, message}`
    -- tables; surface the structured `message` if present so the
    -- 402 body shows the readable reason instead of `table: 0x...`.
    if type(result_or_err) == 'table' and result_or_err.message then
      return nil, 'pay_kit: ' .. tostring(result_or_err.message)
    end
    return nil, tostring(result_or_err)
  end
  if type(result_or_err) ~= 'table' or not result_or_err.reference then
    return nil, 'pay_kit: unexpected MPP verify result'
  end

  return {
    protocol           = 'mpp',
    scheme             = 'charge',
    transaction        = result_or_err.reference,
    settlement_headers = result_or_err.receipt_headers or {},
    raw                = authorization,
  }
end

-- Silence "unused-local" while protocol bits stabilise.
M._unused = { mpp_intents, mpp_protocol, error_codes }

return M
