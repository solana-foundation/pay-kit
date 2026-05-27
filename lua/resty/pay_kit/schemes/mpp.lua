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

local mpp_server = require('mpp.server')
local mpp_intents = require('mpp.protocol.intents.charge')
local mpp_protocol = require('mpp.protocol.solana')
local error_codes  = require('mpp.protocol.core.error_codes')

local M = {}
local Adapter = {}
Adapter.__index = Adapter

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

-- Build a per-gate MPP server. The legacy `mpp.server.new(config)` is
-- bound to one (recipient, currency, decimals, secret_key, realm)
-- tuple; gates with distinct pay_to or currency need distinct server
-- instances. The dispatcher caches these per (recipient, currency,
-- network) tuple.
local function build_mpp_server(config, gate, store)
  local primary_coin = gate:amount():primary_coin()
  local opts = {
    recipient   = gate:pay_to(),
    currency    = primary_coin,
    decimals    = 6,                                -- USDC/USDT/EURC default
    secret_key  = config.mpp.challenge_binding_secret,
    realm       = config.mpp.realm,
    network     = map_pay_kit_network(config.network),
    rpc_url     = config.rpc_url,
    fee_payer_key = nil,                            -- pull-mode: client pays
    store       = store,
  }
  local sgn = config.operator:signer()
  if config.operator:fee_payer() and type(sgn._secret_key_bytes) == 'function' then
    -- Operator's signer doubles as fee payer; pass the raw 64-byte
    -- secret so the inner mpp server can cosign.
    opts.fee_payer_signer_bytes = sgn:_secret_key_bytes()
  end
  return mpp_server.new(opts)
end

-- Build an empty splits[] for now (P5 ships the wire-format only;
-- multi-recipient splits with the verifier-aligned exclusion of the
-- primary recipient land in P6 when the dispatcher wires gate.fees).
local function splits_for(_)
  return nil
end

-- New adapter. `config_resolver` is a `function() return config end`
-- so the adapter can be built once and re-read the (post-configure)
-- pay_kit config on every request. `store` is the replay-protection
-- backing (resolved by the dispatcher).
function M.new(opts)
  opts = opts or {}
  if not opts.config_resolver then
    return nil, 'pay_kit: schemes.mpp.new requires config_resolver'
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
-- formats per RFC 9110.
function Adapter:challenge_headers(gate, _req)
  local server, _config = self:_server_for(gate)
  local amount_units = tostring(gate:total_units())
  local challenge = server:charge(amount_units)
  local headers_mod = require('mpp.protocol.core.headers')
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

  local expected = {
    amount    = tostring(gate:total_units()),
    currency  = gate:amount():primary_coin(),
    recipient = gate:pay_to(),
  }
  local ok, result_or_err = pcall(function()
    return server:verify_credential_with_expected(authorization, expected)
  end)
  if not ok then
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
