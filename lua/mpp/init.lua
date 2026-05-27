-- DEPRECATED: the `mpp` LuaRocks package is being replaced by
-- `lua-resty-pay-kit`. Migrate via `local pay_kit = require('resty.pay_kit')`.
-- This shim emits a warning once per worker on first load and will be
-- removed one minor release after `lua-resty-pay-kit` ships.
local function _pay_kit_deprecation_warn()
  if package.loaded._pay_kit_mpp_warned then return end
  package.loaded._pay_kit_mpp_warned = true
  local ngx_ref = rawget(_G, 'ngx')
  local msg = "DEPRECATION: `require('mpp')` is superseded by " ..
    "`require('resty.pay_kit')` (lua-resty-pay-kit). The mpp shim " ..
    'will be removed one minor release after lua-resty-pay-kit ships.'
  if ngx_ref and ngx_ref.log and ngx_ref.WARN then
    ngx_ref.log(ngx_ref.WARN, msg)
  else
    io.stderr:write('[pay_kit] WARN: ' .. msg .. '\n')
  end
end
_pay_kit_deprecation_warn()

local challenge = require('mpp.protocol.core.challenge')
local headers = require('mpp.protocol.core.headers')
local intents = require('mpp.protocol.intents.charge')
local protocol = require('mpp.protocol.solana')
local store = require('mpp.store')
local types = require('mpp.protocol.core.types')

return {
  server = require('mpp.server'),
  charge_handler = require('mpp.server.charge_handler'),
  solana = {
    rpc = require('mpp.solana.rpc'),
  },
  store = store,
  protocol = {
    core = {
      types = types,
      challenge = challenge,
      headers = headers,
    },
    intents = {
      charge = intents,
    },
    solana = protocol,
  },
  AuthorizationHeader = headers.AUTHORIZATION_HEADER,
  PaymentReceiptHeader = headers.PAYMENT_RECEIPT_HEADER,
  PaymentScheme = headers.PAYMENT_SCHEME,
  WWWAuthenticateHeader = headers.WWW_AUTHENTICATE_HEADER,
  ReceiptStatusSuccess = types.RECEIPT_STATUS_SUCCESS,
  Base64URLEncode = types.base64url_encode,
  Base64URLDecode = types.base64url_decode,
  ComputeChallengeID = challenge.compute_challenge_id,
  ExtractPaymentScheme = headers.extract_payment_scheme,
  FormatAuthorization = headers.format_authorization,
  FormatReceipt = headers.format_receipt,
  FormatWWWAuthenticate = headers.format_www_authenticate,
  NewBase64URLJSONRaw = types.new_base64url_json_raw,
  NewBase64URLJSONValue = types.new_base64url_json_value,
  NewChallengeWithSecret = challenge.new_challenge_with_secret,
  NewChallengeWithSecretFull = challenge.new_challenge_with_secret_full,
  NewPaymentCredential = challenge.new_payment_credential,
  NewMethodName = types.new_method_name,
  NewIntentName = types.new_intent_name,
  ParseAuthorization = headers.parse_authorization,
  ParseReceipt = headers.parse_receipt,
  ParseUnits = intents.parse_units,
  ParseWWWAuthenticate = headers.parse_www_authenticate,
  ParseWWWAuthenticateAll = headers.parse_www_authenticate_all,
}
