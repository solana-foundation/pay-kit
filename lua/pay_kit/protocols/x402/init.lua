--[[
x402 (exact scheme) self-hosted adapter for Lua.

Ports the Ruby gem's `X402::Server::Exact` flow to LuaJIT / OpenResty:
- Builds the v2 `PAYMENT-REQUIRED` envelope.
- Decodes the inbound `PAYMENT-SIGNATURE` credential.
- Matches client-asserted accepted requirement against server offer
  via identity tuple (scheme/network/asset/payTo + canonical extras).
- Verifies the transaction's structural shape against the offer.
- Signs as facilitator (operator.signer fills the facilitator slot).
- Broadcasts via the cosocket-aware pay_kit.solana.rpc client.
- Marks the signature consumed in the replay store.

Delegated mode (`config.x402.facilitator_url` set) is NOT implemented
yet; the dispatcher refuses to bind the adapter and raises
`errors.NOT_IMPLEMENTED` so the design's flag still works.

This adapter handles the common case: a single SPL transferChecked
to the gate's `pay_to`, with the operator paying network fees. Edge
cases the Ruby gem covers (Token-2022, ATA pre-creation toggle,
sol-native scheme) are left as follow-up; they slot into the same
dispatch shape.
]]

local cjson_safe = require('cjson.safe')
local base64_std = require('pay_kit.util.base64_std')
local errors     = require('pay_kit.errors')
local rpc_mod    = require('pay_kit.solana.rpc')
local rpc_transport = require('pay_kit.solana.rpc_transport')
local tx_cosign  = require('pay_kit.solana.tx_cosign')
local x402_verify = require('pay_kit.protocols.x402.exact.verify')
local tx_mod     = require('pay_kit.solana.transaction')
local network_check = require('pay_kit.solana.network_check')

local M = {}
local Adapter = {}
Adapter.__index = Adapter

-- --- constants ------------------------------------------------------

local X402_VERSION_V2 = 2
local PAYMENT_REQUIRED_HEADER  = 'payment-required'
local PAYMENT_SIGNATURE_HEADER = 'payment-signature'
local PAYMENT_RESPONSE_HEADER  = 'payment-response'
local DEFAULT_FIXTURE_SETTLEMENT_HEADER = 'x-payment-settlement-signature'
local DEFAULT_MAX_TIMEOUT_SECONDS = 60
local DEFAULT_DECIMALS = 6
local TOKEN_PROGRAM_BASE58 = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

local CAIP2_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
local CAIP2_DEVNET  = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'

local function caip2_for(pay_kit_network)
  if pay_kit_network == 'solana_mainnet' then return CAIP2_MAINNET end
  return CAIP2_DEVNET                          -- devnet and localnet share devnet CAIP-2
end

-- --- x402 v2 `payment-identifier` extension -------------------------
--
-- Mirrors the rust spine (rust/crates/x402/src/protocol/schemes/exact/
-- types.rs): PaymentExtensions carries a typed `payment-identifier`
-- (kebab-case wire key, #[serde(rename)]) whose `info` is camelCase
-- { required?, id? }, plus a forward-compatible `other` map for unknown
-- extensions that must round-trip verbatim (§5.1.2 echo-and-append).
--
-- The Lua SDK is SERVER-only: it advertises the extension on the
-- PAYMENT-REQUIRED challenge and gates inbound credentials, but does not
-- build outbound credentials (the echo-and-append client path lives in the
-- rust/ts/go/python/swift/kotlin client SDKs). The shapes below exist so the
-- server can publish info.required=true and read back the client's echoed
-- info.id.

local PAYMENT_IDENTIFIER_KEY = 'payment-identifier'

-- Mirror rust's ^[A-Za-z0-9_-]{16,128}$ with an explicit length window plus
-- a character-class match (Lua patterns lack regex quantifier bounds).
local function payment_identifier_id_valid(id)
  if type(id) ~= 'string' then return false end
  if #id < 16 or #id > 128 then return false end
  return id:match('^[A-Za-z0-9_%-]+$') ~= nil
end

-- rust PaymentExtensions::requires_payment_identifier:
-- payment-identifier.info.required == true.
local function extensions_requires_payment_identifier(extensions)
  if type(extensions) ~= 'table' then return false end
  local pid = extensions[PAYMENT_IDENTIFIER_KEY]
  if type(pid) ~= 'table' or type(pid.info) ~= 'table' then return false end
  return pid.info.required == true
end

-- Read the echoed client-side `payment-identifier.info.id` off a decoded
-- credential's extensions, or nil if absent.
local function extensions_payment_identifier_id(extensions)
  if type(extensions) ~= 'table' then return nil end
  local pid = extensions[PAYMENT_IDENTIFIER_KEY]
  if type(pid) ~= 'table' or type(pid.info) ~= 'table' then return nil end
  return pid.info.id
end

-- Build the server-advertised `extensions` object for the PAYMENT-REQUIRED
-- challenge. Mirrors a rust server that sets
-- PaymentRequiredEnvelope.extensions to a payment-identifier with
-- info.required=true. Returns nil when the server does not require one, so
-- the challenge omits the key entirely (rust skip_serializing_if =
-- Option::is_none — never an empty {}/null).
local function advertised_extensions(config)
  local x402_cfg = config.x402 or {}
  if x402_cfg.requires_payment_identifier ~= true then return nil end
  return {
    [PAYMENT_IDENTIFIER_KEY] = {
      info = { required = true },
    },
  }
end

local function network_label(pay_kit_network)
  if pay_kit_network == 'solana_mainnet' then return 'mainnet' end
  if pay_kit_network == 'solana_devnet' then return 'devnet' end
  return 'localnet'
end

-- Match the cross-SDK identity tuple. Mirrors Ruby's
-- `Types.accepted_requirement_matches?` (PR #138). Excludes `amount`
-- and `maxTimeoutSeconds` so v2 credentials whose client omitted
-- amount still match a server offer that includes it.
local REQUIREMENT_IDENTITY_KEYS       = {'scheme', 'network', 'asset', 'payTo'}
local REQUIREMENT_EXTRA_IDENTITY_KEYS = {'feePayer', 'tokenProgram', 'memo'}

local function accepted_requirement_matches(client_accepted, server_offer)
  if type(client_accepted) ~= 'table' or type(server_offer) ~= 'table' then
    return false
  end
  for _, key in ipairs(REQUIREMENT_IDENTITY_KEYS) do
    if client_accepted[key] ~= server_offer[key] then return false end
  end
  local left_extra  = client_accepted.extra or {}
  local right_extra = server_offer.extra or {}
  for _, key in ipairs(REQUIREMENT_EXTRA_IDENTITY_KEYS) do
    if right_extra[key] ~= nil and left_extra[key] ~= right_extra[key] then
      return false
    end
  end
  return true
end

-- --- offer construction --------------------------------------------

-- Fetch a recent blockhash from the server's RPC and stamp it into
-- the challenge's `extra.recentBlockhash` so clients sign against
-- the same chain state the server will broadcast to. Mirrors Ruby
-- PR #142 follow-up: useful on localnet / forked-mainnet (Surfpool)
-- where the client and server can disagree on `latest_blockhash`,
-- and harmless on real networks because the RPC always agrees with
-- itself.
--
-- Scope: this is currently only consumed by the pay-kit Rust client;
-- canonical x402 SDKs ignore `accepted.extra.recentBlockhash` and
-- call `getLatestBlockhash` against their own RPC. Spec discussion
-- to promote `recentBlockhash` (or equivalent) into the canonical
-- `accepted.extra` shape is tracked upstream.
local function fetch_server_blockhash(config)
  if type(config.recent_blockhash_provider) == 'function' then
    local ok, bh = pcall(config.recent_blockhash_provider)
    if ok and type(bh) == 'string' and bh ~= '' then return bh end
    return nil
  end
  if not config.rpc_url or config.rpc_url == '' then return nil end
  local ok_rpc, rpc = pcall(rpc_mod.new,
    {url = config.rpc_url, transport = rpc_transport.new()})
  if not ok_rpc or not rpc then return nil end
  local ok_call, blockhash = pcall(function() return rpc:latest_blockhash() end)
  if not ok_call or type(blockhash) ~= 'string' or blockhash == '' then return nil end
  return blockhash
end

local function exact_requirement(config, gate, resource_path, mint)
  local op_signer = config:effective_x402_signer()
  local extra = {
    feePayer     = op_signer:pubkey(),
    decimals     = DEFAULT_DECIMALS,
    tokenProgram = TOKEN_PROGRAM_BASE58,
    memo         = resource_path,
  }
  local blockhash = fetch_server_blockhash(config)
  if blockhash then extra.recentBlockhash = blockhash end
  local amount = tostring(gate:total_units())
  return {
    scheme              = 'exact',
    network             = caip2_for(config.network),
    asset               = mint,
    amount              = amount,
    maxAmountRequired   = amount,           -- emit both spellings for cross-SDK interop
    payTo               = gate:pay_to(),
    maxTimeoutSeconds   = DEFAULT_MAX_TIMEOUT_SECONDS,
    extra               = extra,
  }
end

local function exact_challenge(config, gate, resource_path)
  local mint = gate:amount():primary_coin()
  local challenge = {
    x402Version = X402_VERSION_V2,
    resource    = {type = 'http', url = resource_path, uri = resource_path},
    accepts     = { exact_requirement(config, gate, resource_path, mint) },
  }
  -- Advertise the v2 `payment-identifier` extension when the route requires
  -- it. Omitted entirely otherwise (rust skip_serializing_if = Option::is_none
  -- on PaymentRequiredEnvelope.extensions).
  local extensions = advertised_extensions(config)
  if extensions then challenge.extensions = extensions end
  return challenge
end

local function encode_payment_required(challenge)
  return base64_std.encode(cjson_safe.encode(challenge))
end

-- --- credential decoding -------------------------------------------

local function decode_payment_signature(header_value)
  if type(header_value) ~= 'string' or header_value == '' then
    return nil, errors.PAYMENT_REQUIRED
  end
  local decoded = base64_std.decode(header_value)
  if not decoded then
    return nil, errors.INVALID_PROOF .. ': payment-signature base64 decode failed'
  end
  local envelope = cjson_safe.decode(decoded)
  if type(envelope) ~= 'table' then
    return nil, errors.INVALID_PROOF .. ': payment-signature not a JSON object'
  end
  if envelope.x402Version ~= X402_VERSION_V2 then
    return nil, errors.INVALID_PROOF .. ': unsupported x402Version'
  end
  return envelope
end

-- --- verifier (structural) -----------------------------------------
--
-- The Ruby gem's 11-rule verifier lives at
-- ruby/lib/x402/protocol/schemes/exact/verify.rb. Lua port focuses on
-- the happy-path subset: single SPL transferChecked to `payTo`, with
-- the credential's claimed amount + memo + token program matching the
-- offer. Edge rules (Token-2022 program id distinction, ATA presence
-- check, sol-native branching) are tracked as follow-up.

-- Run the 11-rule structural verifier + client-signature check. The
-- facilitator key (operator's signer) is the only managed signer; the
-- verifier refuses to accept a credential whose transfer authority or
-- source matches the facilitator (so a malicious credential cannot
-- "spend the facilitator's funds").
local function verify_transaction_shape(transaction_b64, offer, facilitator_b58)
  local managed = {facilitator_b58}
  local ok, transfer = pcall(x402_verify.verify, transaction_b64, offer, managed)
  if not ok then return nil, transfer end
  -- Client signatures must validate against the message bytes BEFORE
  -- the facilitator cosigns, otherwise a malformed envelope leaks
  -- back to a malformed-envelope attacker.
  local sig_ok, sig_err = pcall(x402_verify.verify_client_signatures,
                                transaction_b64, managed)
  if not sig_ok then return nil, sig_err end
  return transfer
end

-- --- broadcast helpers ---------------------------------------------

local function build_rpc(config)
  return rpc_mod.new({url = config.rpc_url, transport = rpc_transport.new()})
end

local function consume_signature(store, signature)
  if not store then return true end
  local key = 'x402-svm-exact:consumed:' .. signature
  if store.put_if_absent then
    return store:put_if_absent(key)
  end
  return true
end

-- --- public API -----------------------------------------------------

function M.new(opts)
  opts = opts or {}
  if not opts.config_resolver then
    return nil, 'pay_kit: protocols.x402.new requires config_resolver'
  end
  return setmetatable({
    _config_resolver = opts.config_resolver,
    _store           = opts.store,
  }, Adapter)
end

function M.detect(headers)
  if type(headers) ~= 'table' then return false end
  local sig = headers[PAYMENT_SIGNATURE_HEADER] or headers['PAYMENT-SIGNATURE']
  return sig ~= nil and sig ~= ''
end

Adapter.detect = function(_, headers) return M.detect(headers) end

function Adapter:accepts_entry(gate, req)
  local config = self._config_resolver()
  local resource = (req and req.path) or '/'
  local req_obj = exact_requirement(config, gate, resource, gate:amount():primary_coin())
  req_obj.protocol = 'x402'
  return req_obj
end

function Adapter:challenge_headers(gate, req)
  local config = self._config_resolver()
  local resource = (req and req.path) or '/'
  local challenge = exact_challenge(config, gate, resource)
  return {
    [PAYMENT_REQUIRED_HEADER] = encode_payment_required(challenge),
  }
end

function Adapter:verify_and_settle(gate, req)
  local config = self._config_resolver()
  local headers = (req and req.headers) or {}
  local credential, err = decode_payment_signature(
    headers[PAYMENT_SIGNATURE_HEADER] or headers['PAYMENT-SIGNATURE']
  )
  if err then return nil, err end

  local resource = (req and req.path) or '/'
  local offer = exact_requirement(config, gate, resource, gate:amount():primary_coin())
  if not accepted_requirement_matches(credential.accepted, offer) then
    return nil, errors.CHARGE_REQUEST_MISMATCH ..
      ': accepted payment requirement does not match server challenge'
  end

  -- x402 v2 `payment-identifier` reject gate. When this route advertised the
  -- extension with info.required=true, the credential MUST echo back a valid
  -- pay_-shaped id (^[A-Za-z0-9_-]{16,128}$); missing, empty, or
  -- pattern-violating ids reject with HTTP 400 semantics. Mirrors the rust
  -- spine (PaymentExtensions::requires_payment_identifier layered onto
  -- verify_envelope_payload; coinbase payment_identifier.md §5.1.2).
  if (config.x402 or {}).requires_payment_identifier == true then
    local id = extensions_payment_identifier_id(credential.extensions)
    if id == nil or id == '' then
      return nil, errors.PAYMENT_IDENTIFIER_REQUIRED ..
        ': credential echoed no id'
    end
    if not payment_identifier_id_valid(id) then
      return nil, errors.PAYMENT_IDENTIFIER_REQUIRED ..
        ': id is invalid: ' .. tostring(id) ..
        ' does not match ^[A-Za-z0-9_-]{16,128}$'
    end
  end

  local payload = credential.payload
  if type(payload) ~= 'table' or type(payload.transaction) ~= 'string' then
    return nil, errors.INVALID_PROOF .. ': payment payload missing transaction'
  end

  if not base64_std.decode(payload.transaction) then
    return nil, errors.INVALID_PROOF .. ': transaction base64 decode failed'
  end

  -- Surfpool localnet sanity check. If the credential was signed on
  -- a Surfpool fixture but the server is configured for a non-localnet
  -- slug, reject up-front with the canonical wrong_network code rather
  -- than letting the broadcast hit the wrong cluster.
  -- Only flag wrong_network for mainnet challenges; the interop matrix
  -- shares devnet's CAIP-2 with surfpool-backed localnet fixtures, so a
  -- devnet label can legitimately carry a Surfpool-prefixed blockhash.
  if config.network == 'solana_mainnet' then
    local parsed_ok, parsed_tx = pcall(tx_mod.from_base64, payload.transaction)
    if parsed_ok and parsed_tx and parsed_tx.message and parsed_tx.message.recent_blockhash then
      local nerr = network_check.check_network_blockhash('mainnet',
        parsed_tx.message.recent_blockhash)
      if nerr then return nil, errors.WRONG_NETWORK end
    end
  end

  local signer = config:effective_x402_signer()
  local transfer, verify_err = verify_transaction_shape(payload.transaction,
    offer, signer:pubkey())
  if not transfer then
    return nil, errors.INVALID_PROOF .. ': ' .. tostring(verify_err)
  end

  -- Sign as facilitator. The operator's signer fills the facilitator
  -- slot. The transaction is already partially signed by the client;
  -- the facilitator inserts its signature at the matching account
  -- index, then broadcasts.
  local secret_bytes = signer._secret_key_bytes and signer:_secret_key_bytes()
  if not secret_bytes then
    return nil, errors.OPERATOR_SIGNER_MISSING ..
      ' (the facilitator slot needs a Local signer with raw bytes)'
  end

  local cosign_ok, cosigned_or_err = pcall(tx_cosign.cosign_base64,
    payload.transaction, secret_bytes)
  if not cosign_ok then
    return nil, errors.INVALID_PROOF .. ': facilitator cosign failed: ' ..
      tostring(cosigned_or_err)
  end
  local cosigned = cosigned_or_err

  -- Broadcast + consume + confirm.
  local rpc = build_rpc(config)
  local broadcast_ok, signature_or_err = pcall(function()
    return rpc:send_raw_transaction(cosigned)
  end)
  if not broadcast_ok then
    return nil, errors.INVALID_PROOF .. ': broadcast failed: ' ..
      tostring(signature_or_err)
  end
  local signature = signature_or_err
  if not signature or signature == '' then
    return nil, errors.INVALID_PROOF .. ': empty broadcast result'
  end

  if not consume_signature(self._store, signature) then
    return nil, errors.SIGNATURE_CONSUMED
  end

  local response_body = cjson_safe.encode({
    success     = true,
    network     = offer.network,
    transaction = signature,
  })
  return {
    protocol           = 'x402',
    scheme             = 'exact',
    transaction        = signature,
    settlement_headers = {
      [PAYMENT_RESPONSE_HEADER] = response_body,
      [DEFAULT_FIXTURE_SETTLEMENT_HEADER] = signature,
    },
    raw                = headers[PAYMENT_SIGNATURE_HEADER] or headers['PAYMENT-SIGNATURE'],
  }
end

-- Test helpers / introspection. Not part of the public API.
M._private = {
  accepted_requirement_matches = accepted_requirement_matches,
  exact_challenge              = exact_challenge,
  exact_requirement            = exact_requirement,
  encode_payment_required      = encode_payment_required,
  decode_payment_signature     = decode_payment_signature,
  network_label                = network_label,
  caip2_for                    = caip2_for,
  advertised_extensions        = advertised_extensions,
  payment_identifier_id_valid  = payment_identifier_id_valid,
  extensions_requires_payment_identifier = extensions_requires_payment_identifier,
  extensions_payment_identifier_id       = extensions_payment_identifier_id,
  PAYMENT_IDENTIFIER_KEY       = PAYMENT_IDENTIFIER_KEY,
}

return M
