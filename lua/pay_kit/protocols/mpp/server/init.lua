local canonical_json = require('pay_kit.util.json')
local challenge = require('pay_kit.protocol.core.challenge')
local error_codes = require('pay_kit.protocol.core.error_codes')
local html_module = require('pay_kit.protocols.mpp.server.html')
local intents = require('pay_kit.protocols.mpp.charge')
local protocol = require('pay_kit.solana.mints')
local solana_verify = require('pay_kit.protocols.mpp.server.solana_verify')
local store = require('pay_kit.protocols.mpp.store')
local types = require('pay_kit.protocol.core.types')
local uint = require('pay_kit.util.uint')

local crypto = require('pay_kit.util._mpp_crypto')

local M = {}

local MIN_SECRET_KEY_BYTES = 32
local CONSUMED_PREFIX = 'solana-charge:consumed:'

-- Audit #15: derive a per-recipient default realm instead of the static
-- shared `"MPP Payment"`. Two servers that share a secret but front
-- different recipients now land in different HMAC credential namespaces, so a
-- credential paid against server A cannot replay against server B. Mirrors the
-- Rust spine `derive_default_realm` (SHA-256 of the recipient, first 4 bytes
-- as a decimal id). Deterministic across restarts for the same recipient.
local function derive_default_realm(recipient)
  local digest = crypto.sha256(recipient)
  local b1, b2, b3, b4 = string.byte(digest, 1, 4)
  local id = ((b1 * 16777216) + (b2 * 65536) + (b3 * 256) + b4) % 100000000
  return string.format('App Id - #%d', id)
end

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

-- Return a copy of `method_details` with the per-request freshness field
-- `recentBlockhash` removed, so two requests that differ only in the
-- blockhash compare equal. Mirrors PHP ChargeServer::comparableRequest
-- (strips methodDetails.recentBlockhash) and Ruby
-- ChallengeStore#comparable_method_details (`(details || {}).except(...)`).
local function comparable_method_details(method_details)
  local out = {}
  if type(method_details) == 'table' then
    for k, v in pairs(method_details) do
      if k ~= 'recentBlockhash' then
        out[k] = v
      end
    end
  end
  return out
end

-- Canonical (RFC 8785) JSON serialization is used for the methodDetails
-- and externalId comparison so field ordering and nested split tables
-- compare structurally, not by Lua table identity. This is the Lua
-- analogue of PHP's Base64Url::encodeJson(canonicalizeArray(...)).
local function canonical(value)
  return canonical_json.encode(value)
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
  -- Audit #24: the secret is the HMAC-SHA256 key binding challenge IDs. A
  -- short / guessable key lets an attacker forge challenge IDs. Enforce a
  -- 32-byte minimum on BOTH the config and the MPP_SECRET_KEY env paths
  -- (NIST SP 800-107: HMAC key >= hash output length). Mirrors the Rust
  -- spine `MIN_SECRET_KEY_BYTES = 32`.
  if #secret_key < MIN_SECRET_KEY_BYTES then
    error(string.format(
      'secret key must be at least %d bytes (got %d); generate one with `openssl rand -base64 32`',
      MIN_SECRET_KEY_BYTES, #secret_key))
  end
  -- Audit #37: reject any network outside the {mainnet, devnet, localnet}
  -- allowlist at boot, before any RPC client / default URL is derived. A typo
  -- or the legacy `mainnet-beta` alias used to silently resolve to mainnet
  -- RPC. Mirrors the Rust spine `validate_network`.
  local network = config.network or 'mainnet'
  local net_ok, net_err = protocol.validate_network(network)
  if not net_ok then
    error(net_err)
  end
  -- Audit #15: explicit empty realm is rejected (an operator typo must not
  -- silently re-introduce the shared-namespace threat). When unset, derive a
  -- per-recipient default.
  local realm
  if config.realm ~= nil then
    if type(config.realm) ~= 'string' or config.realm == '' then
      error('realm must be a non-empty string when provided')
    end
    realm = config.realm
  else
    realm = derive_default_realm(config.recipient)
  end
  -- Audit #16: `feePayer = true` requires a fee-payer key (the server-side
  -- signer's pubkey). Reject the inconsistent boot config so a spec-violating
  -- `feePayer:true` challenge with no `feePayerKey` can never be issued.
  -- Mirrors the Rust spine boot gate.
  local fee_payer = bool_or_nil(config.fee_payer)
  if fee_payer and (config.fee_payer_key == nil or config.fee_payer_key == '') then
    error('fee_payer = true requires fee_payer_key (the server fee-payer pubkey)')
  end
  local currency = config.currency or 'USDC'
  -- Default decimals: SOL uses 9, every SPL stablecoin in our table uses 6.
  -- Caller can still override explicitly.
  local default_decimals = is_native_sol(currency) and 9 or 6
  -- Audit #28 (part 2): resolve the token program at boot. Known stablecoins
  -- resolve from the static table; an arbitrary mint requires an explicit
  -- `config.token_program` or a `config.token_program_resolver` (on-chain
  -- owner lookup) so we never silently assume legacy Token for a Token-2022
  -- mint. SOL resolves to nil.
  local token_program
  if not is_native_sol(currency) then
    if config.token_program ~= nil and config.token_program ~= '' then
      token_program = config.token_program
    else
      local resolved, tp_err = protocol.resolve_token_program(
        currency, network, config.token_program_resolver)
      if tp_err then
        error(tp_err)
      end
      token_program = resolved
    end
  end
  local instance = {
    secret_key = secret_key,
    realm = realm,
    recipient = config.recipient,
    currency = currency,
    decimals = config.decimals or default_decimals,
    network = network,
    token_program = token_program,
    rpc_url = config.rpc_url or protocol.default_rpc_url(network),
    fee_payer = fee_payer,
    fee_payer_key = config.fee_payer_key,
    store = config.store or store.memory(),
    verify_payment = config.verify_payment,
    recent_blockhash = config.recent_blockhash,
    html = config.html or false,
  }
  if instance.verify_payment == nil and config.verifier_hooks ~= nil then
    -- Audit #5: push mode is opt-in (default off). Thread the server config
    -- flag into the signature verifier factory.
    instance.verify_payment = solana_verify.new_signature_verifier(
      config.verifier_hooks, { accept_push_mode = config.accept_push_mode or false })
  end
  return setmetatable(instance, Server)
end

function Server:charge(amount)
  return self:charge_with_options(amount, {})
end

function Server:charge_with_options(amount, options)
  options = options or {}
  local base_units = intents.parse_units(amount, self.decimals)
  -- Tier-0 splits guard. The on-chain primary delta is `amount - sum(splits)`
  -- and the verifier rejects any settled transaction where this drops to
  -- zero or below. Rejecting at challenge issuance time mirrors the Rust /
  -- TypeScript server fixtures and surfaces a canonical 402 with code
  -- `payment_invalid` before any HMAC is computed, so a misconfigured route
  -- (or an harness scenario whose splits sum to the full amount) gets the
  -- same machine-readable code from every SDK.
  if type(options.splits) == 'table' and #options.splits > 0 then
    if #options.splits > 8 then
      error_codes.raise(error_codes.PAYMENT_INVALID, 'too many splits')
    end
    local split_total = '0'
    local seen_recipients = {}
    for i = 1, #options.splits do
      local split = options.splits[i]
      local split_amount = split and split.amount
      -- Audit #21: positive integer amount. `"0"` matches `^%d+$` but a
      -- zero-amount split is meaningless and must be rejected.
      if type(split_amount) ~= 'string' or not split_amount:match('^%d+$') then
        error_codes.raise(error_codes.PAYMENT_INVALID,
          'split.amount must be an integer string')
      end
      if uint.compare(split_amount, '0') <= 0 then
        error_codes.raise(error_codes.PAYMENT_INVALID,
          'split.amount must be greater than zero')
      end
      -- Audit #21: recipient must parse as a Solana pubkey.
      if not protocol.is_pubkey(split.recipient) then
        error_codes.raise(error_codes.PAYMENT_INVALID,
          'split.recipient must be a valid Solana address')
      end
      -- Audit #21: reject duplicate split recipients.
      if seen_recipients[split.recipient] then
        error_codes.raise(error_codes.PAYMENT_INVALID,
          'duplicate split recipient: ' .. tostring(split.recipient))
      end
      seen_recipients[split.recipient] = true
      -- Audit #38: the primary recipient may legitimately appear in splits,
      -- but the combination primary-in-splits + ataCreationRequired in a
      -- fee-sponsored flow is the ATA-recreate drain. Reject only that
      -- combination (matches the Rust spine's narrow misconfig guard).
      if split.recipient == self.recipient and split.ataCreationRequired == true then
        error_codes.raise(error_codes.PAYMENT_INVALID,
          'primary recipient cannot appear in splits with ataCreationRequired = true')
      end
      split_total = uint.add(split_total, split_amount)
    end
    if uint.compare(base_units, split_total) <= 0 then
      error_codes.raise(error_codes.PAYMENT_INVALID,
        'split amounts exceed total amount')
    end
  end
  local method_details = {
    network = self.network,
  }
  if not is_native_sol(self.currency) then
    method_details.decimals = self.decimals
    -- Audit #28: emit the token program resolved (and validated) at boot,
    -- with a per-call override still honored. No silent legacy fallback for
    -- arbitrary mints — `self.token_program` is nil only when boot could not
    -- resolve it, which it would already have rejected for SPL.
    if options.token_program then
      method_details.tokenProgram = options.token_program
    elseif self.token_program then
      method_details.tokenProgram = self.token_program
    end
  end
  -- Audit #16: a per-call fee-payer override must also carry a key, just like
  -- the boot gate. Reject `feePayer:true` with no resolvable feePayerKey so a
  -- spec-violating challenge can never be issued from this path either.
  local want_fee_payer = options.fee_payer or self.fee_payer
  if want_fee_payer then
    local fee_payer_key = options.fee_payer_key or self.fee_payer_key
    if fee_payer_key == nil or fee_payer_key == '' then
      error_codes.raise(error_codes.PAYMENT_INVALID,
        'fee_payer requires a fee_payer_key')
    end
    method_details.feePayer = true
    method_details.feePayerKey = fee_payer_key
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

  -- The three pinned fields are the route's contract with the client:
  -- the same credential issued for a cheaper / different route must not
  -- settle here, even if its HMAC verifies. All three rejections share
  -- the canonical `charge_request_mismatch` code.
  if cred_request.amount ~= expected.amount then
    error_codes.raise(error_codes.CHARGE_REQUEST_MISMATCH, string.format(
      'amount mismatch: credential has %s but endpoint expects %s',
      tostring(cred_request.amount), tostring(expected.amount)
    ))
  end
  if cred_request.currency ~= expected.currency then
    error_codes.raise(error_codes.CHARGE_REQUEST_MISMATCH, string.format(
      'currency mismatch: credential has %s but endpoint expects %s',
      tostring(cred_request.currency), tostring(expected.currency)
    ))
  end
  if cred_request.recipient ~= expected.recipient then
    error_codes.raise(error_codes.CHARGE_REQUEST_MISMATCH,
      'recipient mismatch: credential was issued for a different recipient')
  end

  -- Full route binding. amount/currency/recipient alone are NOT enough
  -- WHEN the route pins an on-chain shape: a credential issued for the same
  -- price and recipient but a different on-chain shape (splits,
  -- feePayer/feePayerKey, tokenProgram, decimals) or a different externalId
  -- must not settle against a route that pins those. Compare the FULL
  -- methodDetails (stripping only the per-request freshness field
  -- recentBlockhash) and the externalId against the route's expected
  -- request. Mirrors PHP ChargeServer::matchesExpectedRequest (canonical
  -- compare after removing methodDetails.recentBlockhash) and Ruby
  -- ChallengeStore#verify_expected (amount/currency/recipient +
  -- comparable_method_details).
  --
  -- The adapter / route-binding path supplies expected.methodDetails (and
  -- optionally expected.externalId), so the full-compare security check
  -- runs there. The documented minimal expected form
  -- {amount, currency, recipient} (methodDetails omitted, externalId
  -- omitted) does NOT pin an on-chain shape, so there is nothing to bind
  -- against: the three pinned fields above are the whole contract. Only
  -- run the methodDetails / externalId binding when the caller actually
  -- supplied them. When omitted, the credential's own methodDetails /
  -- externalId become the settlement defaults (derived below), so settling
  -- from `expected` does not widen the on-chain contract.
  local expected_has_method_details = type(expected.methodDetails) == 'table'
  if expected_has_method_details then
    if canonical(comparable_method_details(cred_request.methodDetails)) ~=
       canonical(comparable_method_details(expected.methodDetails)) then
      error_codes.raise(error_codes.CHARGE_REQUEST_MISMATCH,
        'method details mismatch: credential method details do not match this route')
    end
  end
  if expected.externalId ~= nil then
    if (cred_request.externalId or '') ~= (expected.externalId or '') then
      error_codes.raise(error_codes.CHARGE_REQUEST_MISMATCH,
        'externalId mismatch: credential was issued for a different externalId')
    end
  end

  -- Settlement runs against the ROUTE-expected request, not the
  -- credential's claims. When the route pinned methodDetails, the binding
  -- check above proved the credential's methodDetails equal the route's
  -- (modulo recentBlockhash), so settling from `expected.methodDetails`
  -- cannot widen the on-chain contract. When the caller used the minimal
  -- expected form (methodDetails / externalId omitted), there was nothing
  -- to widen: the credential's own methodDetails / externalId ARE the
  -- contract, so we carry them forward as the settlement defaults. Either
  -- way we keep the credential's recentBlockhash (a freshness value the
  -- client already committed to and the route does not pin) and the
  -- credential description for the receipt.
  local settlement_method_details = {}
  local method_details_source =
    (type(expected.methodDetails) == 'table' and expected.methodDetails)
    or (type(cred_request.methodDetails) == 'table' and cred_request.methodDetails)
    or nil
  if method_details_source then
    for k, v in pairs(method_details_source) do
      settlement_method_details[k] = v
    end
  end
  if settlement_method_details.recentBlockhash == nil
     and type(cred_request.methodDetails) == 'table'
     and cred_request.methodDetails.recentBlockhash ~= nil then
    settlement_method_details.recentBlockhash = cred_request.methodDetails.recentBlockhash
  end
  local settlement_request = {
    amount = expected.amount,
    currency = expected.currency,
    recipient = expected.recipient,
    methodDetails = settlement_method_details,
    externalId = expected.externalId or cred_request.externalId,
    description = cred_request.description,
  }
  return self:_finalize_verification(credential_value, settlement_request, payload)
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
    error_codes.raise(error_codes.CHALLENGE_VERIFICATION_FAILED, 'challenge ID mismatch')
  end
  if challenge_value:is_expired(now_epoch or os.time()) then
    error_codes.raise(error_codes.CHALLENGE_EXPIRED,
      'challenge expired at ' .. tostring(challenge_value.expires))
  end

  local request, decode_err = challenge_value.request:decode()
  if not request then
    error_codes.raise(error_codes.CHALLENGE_VERIFICATION_FAILED, tostring(decode_err))
  end

  -- Tier-2: pinned-field backstop.
  self:_verify_pinned_fields(echoed, request)

  local method_details = request.methodDetails or {}
  local payload = challenge.payload_as(credential_value) or {}
  local payload_type = payload.type
  if payload_type ~= 'transaction' and payload_type ~= 'signature' then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'missing or invalid payload type')
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
  -- Tier-2 cross-route checks. method/intent/realm mismatches are
  -- canonically `challenge_route_mismatch` (the credential was issued
  -- under a different routing identity). currency/recipient mismatches
  -- here are also a route-level rejection (same realm but the server's
  -- configured currency or recipient differs); they share the same code
  -- because the route is what changed, not the credential's contents.
  local method_name = 'solana'
  if echoed.method ~= method_name then
    error_codes.raise(error_codes.CHALLENGE_ROUTE_MISMATCH, string.format(
      "credential method '%s' does not match this server (expected '%s')",
      tostring(echoed.method), method_name
    ))
  end
  if not types.is_charge_intent(echoed.intent) then
    error_codes.raise(error_codes.CHALLENGE_ROUTE_MISMATCH,
      string.format("credential intent '%s' is not a charge", tostring(echoed.intent)))
  end
  -- HMAC ID is computed using the server's own realm (not the echoed one),
  -- so a tampered echoed realm passes HMAC unless re-signed. Pin it here.
  if echoed.realm ~= self.realm then
    error_codes.raise(error_codes.CHALLENGE_ROUTE_MISMATCH, string.format(
      "credential realm '%s' does not match this server (expected '%s')",
      tostring(echoed.realm), tostring(self.realm)
    ))
  end
  if request.currency ~= self.currency then
    error_codes.raise(error_codes.CHALLENGE_ROUTE_MISMATCH, string.format(
      "credential currency '%s' does not match this server (expected '%s')",
      tostring(request.currency), tostring(self.currency)
    ))
  end
  if request.recipient ~= self.recipient then
    error_codes.raise(error_codes.CHALLENGE_ROUTE_MISMATCH,
      'credential recipient does not match this server')
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
    error_codes.raise(error_codes.PAYMENT_INVALID,
      'verification result must include a reference')
  end

  -- Settlement layers that already consumed the replay marker themselves
  -- (e.g. `charge_handler:as_callback()` which writes
  -- `solana-charge:consumed:<sig>` inside `settle_pull` before await, and
  -- `solana_verify.verify_transaction` which writes the same key between
  -- broadcast and await for the L8 ordering fix) signal back via
  -- `result.consumed = true`. Skip the outer put_if_absent in that case so
  -- the same marker is not re-asserted against the shared store. When the
  -- verifier supplies its own `replay_key` we also know the consume already
  -- happened, so honoring `consumed` here keeps the Kong / OpenResty
  -- wiring (shared replay store between charge_handler and Server) from
  -- double-asserting and returning a spurious `signature_consumed` on the
  -- first valid payment. Push-mode signature verifiers that do not consume
  -- themselves fall through to the outer guard.
  if result.consumed ~= true then
    local replay_key = result.replay_key or (CONSUMED_PREFIX .. reference)
    local inserted = self.store:put_if_absent(replay_key, true)
    if not inserted then
      error_codes.raise(error_codes.SIGNATURE_CONSUMED, 'payment already consumed')
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
