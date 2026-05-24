local challenge = require('mpp.protocol.core.challenge')
local html_module = require('mpp.server.html')
local intents = require('mpp.protocol.intents.charge')
local protocol = require('mpp.protocol.solana')
local solana_verify = require('mpp.server.solana_verify')
local store = require('mpp.store')
local types = require('mpp.protocol.core.types')

local M = {}

local DEFAULT_REALM = 'MPP Payment'
local CONSUMED_PREFIX = 'solana-charge:consumed:'

local Server = {}
Server.__index = Server

local function is_native_sol(currency)
  return string.lower(currency or '') == 'sol'
end

local function bool_or_nil(value)
  if value == nil then
    return nil
  end
  return value and true or false
end

function M.new(config)
  if type(config) ~= 'table' then
    error('config table is required')
  end
  if type(config.recipient) ~= 'string' or config.recipient == '' then
    error('recipient is required')
  end
  local secret_key = config.secret_key or os.getenv('MPP_SECRET_KEY')
  if secret_key == nil or secret_key == '' then
    error('missing secret key')
  end
  local currency = config.currency or 'USDC'
  -- Default decimals: SOL uses 9, every SPL stablecoin in our table uses 6.
  -- Caller can still override explicitly.
  local default_decimals = is_native_sol(currency) and 9 or 6
  local instance = {
    secret_key = secret_key,
    realm = config.realm or DEFAULT_REALM,
    recipient = config.recipient,
    currency = currency,
    decimals = config.decimals or default_decimals,
    network = config.network or 'mainnet',
    rpc_url = config.rpc_url or protocol.default_rpc_url(config.network or 'mainnet'),
    fee_payer = bool_or_nil(config.fee_payer),
    fee_payer_key = config.fee_payer_key,
    store = config.store or store.memory(),
    verify_payment = config.verify_payment,
    recent_blockhash = config.recent_blockhash,
    html = config.html or false,
  }
  if instance.verify_payment == nil and config.verifier_hooks ~= nil then
    instance.verify_payment = solana_verify.new_signature_verifier(config.verifier_hooks)
  end
  return setmetatable(instance, Server)
end

function Server:charge(amount)
  return self:charge_with_options(amount, {})
end

function Server:charge_with_options(amount, options)
  options = options or {}
  local base_units = intents.parse_units(amount, self.decimals)
  local method_details = {
    network = self.network,
  }
  if not is_native_sol(self.currency) then
    method_details.decimals = self.decimals
    if options.token_program then
      method_details.tokenProgram = options.token_program
    elseif protocol.stablecoin_symbol(self.currency) then
      method_details.tokenProgram = protocol.default_token_program_for_currency(self.currency, self.network)
    end
  end
  if options.fee_payer or self.fee_payer then
    method_details.feePayer = true
    if options.fee_payer_key or self.fee_payer_key then
      method_details.feePayerKey = options.fee_payer_key or self.fee_payer_key
    end
  end
  if options.splits then
    method_details.splits = options.splits
  end
  if options.recent_blockhash or self.recent_blockhash then
    method_details.recentBlockhash = options.recent_blockhash or self.recent_blockhash
  end
  local request = types.new_base64url_json_value({
    amount = base_units,
    currency = self.currency,
    recipient = self.recipient,
    description = options.description,
    externalId = options.external_id,
    methodDetails = method_details,
  })
  return challenge.new_challenge_with_secret_full(
    self.secret_key,
    self.realm,
    types.new_method_name('solana'),
    types.new_intent_name('charge'),
    request,
    options.expires,
    nil,
    options.description,
    nil
  )
end

--- Verify a credential (simple API).
--
-- This is appropriate for servers that only gate a single route. Servers that
-- gate multiple routes at different prices on the same secret key MUST use
-- ``verify_credential_with_expected`` so the route's expected amount is
-- compared to the credential's claimed amount; otherwise a credential issued
-- for a cheaper route can be replayed at an expensive one.
--
-- A Tier-2 pinned-field check inside this method also enforces that the
-- credential's method/intent/realm/currency/recipient match the server's
-- configuration, so cross-route replay across instances with different
-- recipients/currencies is blocked.
function Server:verify_credential(credential_value, now_epoch)
  local request, _method_details, payload = self:_verify_challenge_and_decode(credential_value, now_epoch)
  return self:_finalize_verification(credential_value, request, payload)
end

--- Verify a credential against the route's expected charge request.
--
-- The amount/currency/recipient on the credential's claimed challenge must
-- match ``expected``. Settlement (the user-supplied verify_payment callback)
-- then runs against ``expected`` — not the credential's claims — so a
-- credential built for a different route's request cannot succeed.
function Server:verify_credential_with_expected(credential_value, expected, now_epoch)
  if type(expected) ~= 'table' then
    error('expected request table is required')
  end
  local cred_request, _method_details, payload = self:_verify_challenge_and_decode(credential_value, now_epoch)

  if cred_request.amount ~= expected.amount then
    error(string.format(
      'amount mismatch: credential has %s but endpoint expects %s',
      tostring(cred_request.amount), tostring(expected.amount)
    ))
  end
  if cred_request.currency ~= expected.currency then
    error(string.format(
      'currency mismatch: credential has %s but endpoint expects %s',
      tostring(cred_request.currency), tostring(expected.currency)
    ))
  end
  if cred_request.recipient ~= expected.recipient then
    error('recipient mismatch: credential was issued for a different recipient')
  end

  return self:_finalize_verification(credential_value, expected, payload)
end

--- Tier-1 (HMAC + expiry) and Tier-2 (pinned-field) checks.
--
-- Returns the credential-decoded ``request``, parsed ``method_details``, and
-- the credential payload for downstream settlement.
function Server:_verify_challenge_and_decode(credential_value, now_epoch)
  local echoed = credential_value.challenge
  local challenge_value = challenge.challenge_from_table({
    id = echoed.id,
    realm = echoed.realm,
    method = echoed.method,
    intent = echoed.intent,
    request = echoed.request:raw(),
    expires = echoed.expires,
    digest = echoed.digest,
    opaque = echoed.opaque and echoed.opaque:raw() or nil,
  })

  if not challenge_value:verify(self.secret_key) then
    error('challenge ID mismatch')
  end
  if challenge_value:is_expired(now_epoch or os.time()) then
    error('challenge expired at ' .. tostring(challenge_value.expires))
  end

  local request, decode_err = challenge_value.request:decode()
  if not request then
    error(decode_err)
  end

  -- Tier-2: pinned-field backstop.
  self:_verify_pinned_fields(echoed, request)

  local method_details = request.methodDetails or {}
  local payload = challenge.payload_as(credential_value) or {}
  local payload_type = payload.type
  if payload_type ~= 'transaction' and payload_type ~= 'signature' then
    error('missing or invalid payload type')
  end
  if payload_type == 'signature' and method_details.feePayer then
    -- B34: keep this message byte-identical to the verifier-layer B34
    -- reject in solana_verify.lua so the canonical-codes classifier
    -- and any text-based log monitor see the same string from either
    -- layer. Divergence would force the classifier to learn two
    -- patterns for the same condition.
    error('Push-mode credentials are not allowed when the route uses a server-side fee payer')
  end

  return request, method_details, payload
end

function Server:_verify_pinned_fields(echoed, request)
  local method_name = 'solana'
  if echoed.method ~= method_name then
    error(string.format(
      "credential method '%s' does not match this server (expected '%s')",
      tostring(echoed.method), method_name
    ))
  end
  if not types.is_charge_intent(echoed.intent) then
    error(string.format("credential intent '%s' is not a charge", tostring(echoed.intent)))
  end
  -- HMAC ID is computed using the server's own realm (not the echoed one),
  -- so a tampered echoed realm passes HMAC unless re-signed. Pin it here.
  if echoed.realm ~= self.realm then
    error(string.format(
      "credential realm '%s' does not match this server (expected '%s')",
      tostring(echoed.realm), tostring(self.realm)
    ))
  end
  if request.currency ~= self.currency then
    error(string.format(
      "credential currency '%s' does not match this server (expected '%s')",
      tostring(request.currency), tostring(self.currency)
    ))
  end
  if request.recipient ~= self.recipient then
    error('credential recipient does not match this server')
  end
end

function Server:_finalize_verification(credential_value, request, payload)
  local method_details = request.methodDetails or {}
  if type(self.verify_payment) ~= 'function' then
    error('verify_payment callback is required')
  end

  local result = self.verify_payment({
    payload = payload,
    request = request,
    method_details = method_details,
    credential = credential_value,
    store = self.store,
    server = self,
  }) or {}

  local reference = result.reference or payload.signature or payload.transaction
  if reference == nil or reference == '' then
    error('verification result must include a reference')
  end

  local replay_key = result.replay_key or (CONSUMED_PREFIX .. reference)
  -- L8 ordering: in pull mode, solana_verify.verify_transaction now
  -- writes the consume marker between broadcast and await_confirmation
  -- and signals back via result.consumed=true. Skip the outer
  -- put_if_absent in that case so we do not double-consume our own
  -- marker. In push mode (signature credentials) and any other path
  -- where the verifier did not consume, fall back to the outer guard
  -- so the L4 lock still applies.
  if result.consumed ~= true then
    local inserted = self.store:put_if_absent(replay_key, true)
    if not inserted then
      error('payment already consumed')
    end
  end

  return challenge.new_receipt({
    method = 'solana',
    timestamp = result.timestamp or os.date('!%Y-%m-%dT%H:%M:%SZ'),
    reference = reference,
    challengeId = credential_value.challenge.id,
    externalId = request.externalId,
    status = result.status or types.RECEIPT_STATUS_SUCCESS,
  })
end

function Server:html_enabled()
  return self.html
end

function Server:challenge_to_html(challenge_value)
  return html_module.challenge_to_html(challenge_value, self.rpc_url)
end

M.Server = Server

return M
