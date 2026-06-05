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

-- Legacy and current protocol versions. We mirror the rust spine's
-- X402_VERSION_V1 / X402_VERSION_V2 constant naming (constants.rs:10,13);
-- per the no-version-suffix naming rule for NEW symbols, every wire shape
-- introduced here is named by its structure, not by a v1/v2 suffix.
local X402_VERSION_V1 = 1
local X402_VERSION_V2 = 2

-- v2 wire headers (canonical, lowercased for the OpenResty header table).
local PAYMENT_REQUIRED_HEADER  = 'payment-required'
local PAYMENT_SIGNATURE_HEADER = 'payment-signature'
local PAYMENT_RESPONSE_HEADER  = 'payment-response'

-- Legacy v1 wire headers (rust constants.rs:16-22). The v1 credential and
-- settlement travel on the X-PAYMENT* header family; the credential header
-- is X-PAYMENT (a standard-base64 envelope whose scheme and network sit as
-- top-level siblings of payload, with no accepted), and the settlement is
-- emitted on X-PAYMENT-RESPONSE. The v1 challenge-request header
-- (X-PAYMENT-REQUIRED) is a producer concern: this server emits v2
-- challenges by default, so it never reads or writes that header.
local LEGACY_PAYMENT_HEADER          = 'x-payment'
local LEGACY_PAYMENT_RESPONSE_HEADER = 'x-payment-response'

local DEFAULT_FIXTURE_SETTLEMENT_HEADER = 'x-payment-settlement-signature'
local DEFAULT_MAX_TIMEOUT_SECONDS = 60
local DEFAULT_DECIMALS = 6
local TOKEN_PROGRAM_BASE58 = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

local CAIP2_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
local CAIP2_DEVNET  = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'
local CAIP2_TESTNET = 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z'

-- Plain SVM network slugs the legacy v1 wire carries instead of CAIP-2.
local LEGACY_NETWORK_SOLANA  = 'solana'
local LEGACY_NETWORK_DEVNET  = 'solana-devnet'
local LEGACY_NETWORK_TESTNET = 'solana-testnet'

local function caip2_for(pay_kit_network)
  if pay_kit_network == 'solana_mainnet' then return CAIP2_MAINNET end
  return CAIP2_DEVNET                          -- devnet and localnet share devnet CAIP-2
end

-- Normalize any network identifier (CAIP-2 or plain legacy slug) to its
-- CAIP-2 form so the v1 and v2 network gates share a comparison basis.
-- Mirrors rust caip2_network_for_cluster (types.rs:31-39): plain
-- "solana" / "mainnet" -> mainnet CAIP-2; "solana-devnet" / "devnet" /
-- "localnet" -> devnet CAIP-2; the CAIP-2 forms map to themselves.
local function caip2_network_for_cluster(network)
  if type(network) ~= 'string' then return '' end
  if network == LEGACY_NETWORK_SOLANA or network == 'mainnet'
    or network == 'mainnet-beta' or network == CAIP2_MAINNET then
    return CAIP2_MAINNET
  end
  if network == LEGACY_NETWORK_DEVNET or network == 'devnet'
    or network == 'localnet' or network == CAIP2_DEVNET then
    return CAIP2_DEVNET
  end
  if network == LEGACY_NETWORK_TESTNET or network == 'testnet'
    or network == CAIP2_TESTNET then
    return CAIP2_TESTNET
  end
  return network
end

-- Map a pay-kit network to the plain SVM slug the legacy v1 settlement
-- response carries. Mirrors rust v1_network_for_requirements
-- (client/exact/payment.rs:393-404): devnet-family -> "solana-devnet",
-- everything else -> "solana". (testnet stays available for completeness;
-- the operator network only ever resolves to mainnet or devnet today.)
local function legacy_network_slug(pay_kit_network)
  if pay_kit_network == 'solana_devnet' or pay_kit_network == 'solana_localnet' then
    return LEGACY_NETWORK_DEVNET
  end
  if pay_kit_network == 'solana_testnet' then
    return LEGACY_NETWORK_TESTNET
  end
  return LEGACY_NETWORK_SOLANA
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
  return {
    x402Version = X402_VERSION_V2,
    resource    = {type = 'http', url = resource_path, uri = resource_path},
    accepts     = { exact_requirement(config, gate, resource_path, mint) },
  }
end

local function encode_payment_required(challenge)
  return base64_std.encode(cjson_safe.encode(challenge))
end

-- --- credential decoding -------------------------------------------

-- Decode a standard-base64 JSON credential envelope. The bytes are shared
-- between the v1 X-PAYMENT and the v2 PAYMENT-SIGNATURE wires (rust decodes
-- both via STANDARD base64, server/exact.rs:308); the version dispatch
-- happens at the call site so each wire keeps its native shape.
local function decode_envelope(header_value, label)
  if type(header_value) ~= 'string' or header_value == '' then
    return nil, errors.PAYMENT_REQUIRED
  end
  local decoded = base64_std.decode(header_value)
  if not decoded then
    return nil, errors.INVALID_PROOF .. ': ' .. label .. ' base64 decode failed'
  end
  local envelope = cjson_safe.decode(decoded)
  if type(envelope) ~= 'table' then
    return nil, errors.INVALID_PROOF .. ': ' .. label .. ' not a JSON object'
  end
  return envelope
end

-- Decode the v2 PAYMENT-SIGNATURE credential. v2 envelopes carry an
-- `accepted` object and x402Version=2; the accepted-vs-offer identity match
-- and the field comparison are run by the caller.
local function decode_payment_signature(header_value)
  local envelope, err = decode_envelope(header_value, 'payment-signature')
  if err then return nil, err end
  if envelope.x402Version ~= X402_VERSION_V2 then
    return nil, errors.INVALID_PROOF .. ': unsupported x402Version'
  end
  return envelope
end

-- Decode a legacy v1 X-PAYMENT credential. The v1 envelope carries
-- x402Version=1, scheme + network as top-level siblings of payload, and no
-- accepted object (rust PaymentSignatureEnvelope, types.rs:587-608). The
-- caller normalizes the plain network slug and runs the network gate; there
-- is no accepted-vs-offer comparison because v1 has no accepted object
-- (rust parse_payment_signature v1 arm, server/exact.rs:316-327).
local function decode_legacy_payment(header_value)
  local envelope, err = decode_envelope(header_value, 'x-payment')
  if err then return nil, err end
  if envelope.x402Version ~= X402_VERSION_V1 then
    return nil, errors.INVALID_PROOF .. ': unsupported x402Version'
  end
  if envelope.scheme ~= 'exact' then
    return nil, errors.INVALID_PROOF .. ': x-payment scheme is not exact'
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

-- Read the v2 credential header (PAYMENT-SIGNATURE) from a header table,
-- tolerating the canonical-cased key OpenResty does not lowercase.
local function read_payment_signature(headers)
  return headers[PAYMENT_SIGNATURE_HEADER] or headers['PAYMENT-SIGNATURE']
end

-- Read the legacy v1 credential header (X-PAYMENT) from a header table.
local function read_legacy_payment(headers)
  return headers[LEGACY_PAYMENT_HEADER] or headers['X-PAYMENT']
end

function M.detect(headers)
  if type(headers) ~= 'table' then return false end
  -- Dual-accept: the v2 PAYMENT-SIGNATURE wire is read first, then the
  -- legacy v1 X-PAYMENT wire. A request carrying either credential is ours.
  local sig = read_payment_signature(headers)
  if sig ~= nil and sig ~= '' then return true end
  local legacy = read_legacy_payment(headers)
  return legacy ~= nil and legacy ~= ''
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

-- Classify a decoded credential by its x402Version FIELD (not by which
-- header carried it), mirroring rust parse_payment_signature which decodes
-- once and matches on envelope.x402_version (server/exact.rs:315-347): v2 ->
-- canonical, v1 -> legacy (scheme must be exact), anything else -> reject.
-- Returns (is_legacy, err).
local function classify_credential(envelope)
  local version = envelope.x402Version
  if version == X402_VERSION_V2 then
    return false, nil
  elseif version == X402_VERSION_V1 then
    if envelope.scheme ~= 'exact' then
      return nil, errors.INVALID_PROOF .. ': x-payment scheme is not exact'
    end
    return true, nil
  end
  return nil, errors.INVALID_PROOF .. ': unsupported x402Version'
end

-- Resolve the inbound credential under the dual-accept rule: read the v2
-- PAYMENT-SIGNATURE wire FIRST, then fall back to the legacy v1 X-PAYMENT
-- wire. Returns (envelope, is_legacy, raw_header) or (nil, err). Dispatch is
-- CONTENT-BASED: whichever header carried the credential, it is decoded once
-- and classified on its x402Version field (so a v1 envelope is honoured even
-- if it arrived on PAYMENT-SIGNATURE, and a genuinely-unknown version is
-- still rejected) -- matching rust parse_payment_signature (server/exact.rs:315-347).
local function resolve_credential(headers)
  local v2_header = read_payment_signature(headers)
  if type(v2_header) == 'string' and v2_header ~= '' then
    local envelope, err = decode_envelope(v2_header, 'payment-signature')
    if err then return nil, nil, nil, err end
    local is_legacy, cerr = classify_credential(envelope)
    if cerr then return nil, nil, nil, cerr end
    return envelope, is_legacy, v2_header
  end
  local legacy_header = read_legacy_payment(headers)
  if type(legacy_header) == 'string' and legacy_header ~= '' then
    local envelope, err = decode_envelope(legacy_header, 'x-payment')
    if err then return nil, nil, nil, err end
    local is_legacy, cerr = classify_credential(envelope)
    if cerr then return nil, nil, nil, cerr end
    return envelope, is_legacy, legacy_header
  end
  return nil, nil, nil, errors.PAYMENT_REQUIRED
end

function Adapter:verify_and_settle(gate, req)
  local config = self._config_resolver()
  local headers = (req and req.headers) or {}
  local credential, is_legacy, raw_header, err = resolve_credential(headers)
  if err then return nil, err end

  local resource = (req and req.path) or '/'
  local offer = exact_requirement(config, gate, resource, gate:amount():primary_coin())

  if is_legacy then
    -- v1 binds only scheme + network (no accepted object). Normalize the
    -- plain SVM slug and gate it against the server's CAIP-2, mirroring the
    -- rust v1 arm (server/exact.rs:316-327). The facilitator MUST-checks
    -- below are identical to v2 (both reach verify_transaction_shape).
    if caip2_network_for_cluster(credential.network or '') ~= caip2_for(config.network) then
      return nil, errors.WRONG_NETWORK ..
        ': x-payment network does not match server challenge'
    end
  else
    -- v2 binds the full accepted requirement against the server offer.
    if not accepted_requirement_matches(credential.accepted, offer) then
      return nil, errors.CHARGE_REQUEST_MISMATCH ..
        ': accepted payment requirement does not match server challenge'
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

  -- Settlement response. v1 emits X-PAYMENT-RESPONSE carrying the plain SVM
  -- network slug and the payer pubkey (rust v1 settlement shape
  -- { success, transaction, network, payer }); v2 emits PAYMENT-RESPONSE
  -- with the CAIP-2 network from the offer.
  local settlement_headers = {
    [DEFAULT_FIXTURE_SETTLEMENT_HEADER] = signature,
  }
  if is_legacy then
    settlement_headers[LEGACY_PAYMENT_RESPONSE_HEADER] = cjson_safe.encode({
      success     = true,
      transaction = signature,
      network     = credential.network or legacy_network_slug(config.network),
      payer       = transfer and transfer.authority or nil,
    })
  else
    settlement_headers[PAYMENT_RESPONSE_HEADER] = cjson_safe.encode({
      success     = true,
      network     = offer.network,
      transaction = signature,
    })
  end

  return {
    protocol           = 'x402',
    scheme             = 'exact',
    transaction        = signature,
    settlement_headers = settlement_headers,
    raw                = raw_header,
  }
end

-- Test helpers / introspection. Not part of the public API.
M._private = {
  accepted_requirement_matches = accepted_requirement_matches,
  exact_challenge              = exact_challenge,
  exact_requirement            = exact_requirement,
  encode_payment_required      = encode_payment_required,
  decode_payment_signature     = decode_payment_signature,
  decode_legacy_payment        = decode_legacy_payment,
  resolve_credential           = resolve_credential,
  network_label                = network_label,
  caip2_for                    = caip2_for,
  caip2_network_for_cluster    = caip2_network_for_cluster,
  legacy_network_slug          = legacy_network_slug,
  LEGACY_PAYMENT_HEADER          = LEGACY_PAYMENT_HEADER,
  LEGACY_PAYMENT_RESPONSE_HEADER = LEGACY_PAYMENT_RESPONSE_HEADER,
}

return M
