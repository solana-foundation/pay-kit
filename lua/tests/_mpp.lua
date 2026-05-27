--[[
Test-only aggregator that bundles the protocol-level MPP surface
under one table. The pre-refactor `mpp/init.lua` exposed the same
shape; production callers should use the granular `pay_kit.*`
modules directly. Keeping this aggregator in tests/ makes the
intent obvious: a fixture, not a public re-export.
]]

local challenge = require('pay_kit.protocol.core.challenge')
local headers   = require('pay_kit.protocol.core.headers')
local intents   = require('pay_kit.protocols.mpp.charge')
local protocol  = require('pay_kit.solana.mints')
local store     = require('pay_kit.protocols.mpp.store')
local types     = require('pay_kit.protocol.core.types')

return {
  server         = require('pay_kit.protocols.mpp.server'),
  charge_handler = require('pay_kit.protocols.mpp.server.charge_handler'),
  solana = {
    rpc = require('pay_kit.solana.rpc'),
  },
  store = store,
  protocol = {
    core = {
      types     = types,
      challenge = challenge,
      headers   = headers,
    },
    intents = {
      charge = intents,
    },
    solana = protocol,
  },

  AuthorizationHeader        = headers.AUTHORIZATION_HEADER,
  PaymentReceiptHeader       = headers.PAYMENT_RECEIPT_HEADER,
  PaymentScheme              = headers.PAYMENT_SCHEME,
  WWWAuthenticateHeader      = headers.WWW_AUTHENTICATE_HEADER,
  ReceiptStatusSuccess       = types.RECEIPT_STATUS_SUCCESS,
  Base64URLEncode            = types.base64url_encode,
  Base64URLDecode            = types.base64url_decode,
  ComputeChallengeID         = challenge.compute_challenge_id,
  ExtractPaymentScheme       = headers.extract_payment_scheme,
  FormatAuthorization        = headers.format_authorization,
  FormatReceipt              = headers.format_receipt,
  FormatWWWAuthenticate      = headers.format_www_authenticate,
  NewBase64URLJSONRaw        = types.new_base64url_json_raw,
  NewBase64URLJSONValue      = types.new_base64url_json_value,
  NewChallengeWithSecret     = challenge.new_challenge_with_secret,
  NewChallengeWithSecretFull = challenge.new_challenge_with_secret_full,
  NewPaymentCredential       = challenge.new_payment_credential,
  NewMethodName              = types.new_method_name,
  NewIntentName              = types.new_intent_name,
  ParseAuthorization         = headers.parse_authorization,
  ParseReceipt               = headers.parse_receipt,
  ParseUnits                 = intents.parse_units,
  ParseWWWAuthenticate       = headers.parse_www_authenticate,
  ParseWWWAuthenticateAll    = headers.parse_www_authenticate_all,
}
