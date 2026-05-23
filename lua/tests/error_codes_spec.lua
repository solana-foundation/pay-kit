local helper = require('tests.test_helper')
local mpp = require('mpp')
local error_codes = require('mpp.protocol.core.error_codes')
local network_check = require('mpp.server.network_check')

-- Drive every code path that the Lua server's 402 surface emits and
-- assert each rejection carries the right canonical code. Mirrors the
-- Python L6 audit row: every server-side failure must distinguish itself
-- from the others by a machine-readable code, not just a human string.

local TEST_RECIPIENT = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h'
local TEST_SECRET = 'mpp-test-secret-key'

local function build_server(opts)
  opts = opts or {}
  return mpp.server.new({
    recipient = opts.recipient or TEST_RECIPIENT,
    currency = opts.currency or 'USDC',
    decimals = 6,
    network = opts.network or 'mainnet-beta',
    secret_key = opts.secret_key or TEST_SECRET,
    realm = opts.realm or 'MPP Test',
    store = mpp.store.memory(),
    verify_payment = opts.verify_payment or function()
      return { reference = 'stub-reference' }
    end,
  })
end

-- Build a valid Authorization: Payment credential against an issued challenge.
-- Uses payload type='signature' so the on-chain settlement stub is the
-- only thing the verify_payment callback has to handle.
local function build_credential(challenge_value)
  return mpp.NewPaymentCredential(challenge_value:to_echo(), {
    type = 'signature',
    signature = 'stub-signature',
  })
end

-- Re-sign a tampered echo so it passes the Tier-1 HMAC check and the
-- pinned-field Tier-2 check is the one that bites. Mirrors the helper in
-- tests/cross_route_replay_spec.lua.
local function resign_echo(echo, secret)
  echo.id = mpp.ComputeChallengeID(
    secret,
    echo.realm,
    echo.method,
    echo.intent,
    echo.request:raw(),
    echo.expires or '',
    echo.digest or '',
    (echo.opaque and echo.opaque:raw()) or nil
  )
end

-- Extract the code from a pcall'd error value via the canonical projector.
local function code_of(err)
  return error_codes.to_response(err).code
end

helper.test('error_codes.raise rejects an unknown code at the source', function()
  helper.assert_error(function()
    error_codes.raise('not_a_real_code', 'should never reach the response builder')
  end, 'invalid error code')
end)

helper.test('error_codes.raise produces a table with code and message fields', function()
  local ok, err = pcall(error_codes.raise,
    error_codes.PAYMENT_INVALID, 'shape rejection')
  helper.assert_equal(ok, false)
  helper.assert_equal(type(err), 'table')
  helper.assert_equal(err.code, error_codes.PAYMENT_INVALID)
  helper.assert_equal(err.message, 'shape rejection')
end)

helper.test('error_codes.to_response preserves a canonical code unchanged', function()
  local response = error_codes.to_response({
    code = error_codes.SIGNATURE_CONSUMED,
    message = 'payment already consumed',
  })
  helper.assert_equal(response.code, error_codes.SIGNATURE_CONSUMED)
  helper.assert_equal(response.error, 'payment already consumed')
  helper.assert_equal(response.message, 'payment already consumed')
end)

helper.test('error_codes.to_response defaults bare-string errors to challenge_verification_failed', function()
  local response = error_codes.to_response('some legacy bare string error')
  helper.assert_equal(response.code, error_codes.CHALLENGE_VERIFICATION_FAILED)
  helper.assert_equal(response.error, 'some legacy bare string error')
end)

helper.test('error_codes.to_response rewrites a non-canonical table code to the default', function()
  local response = error_codes.to_response({
    code = 'verification-error', -- pre-L6 legacy shape
    message = 'something went wrong',
  })
  helper.assert_equal(response.code, error_codes.CHALLENGE_VERIFICATION_FAILED)
  helper.assert_equal(response.message, 'something went wrong')
end)

helper.test('server emits charge_request_mismatch on amount mismatch', function()
  local server = build_server()
  local challenge = server:charge('0.001')
  local credential = build_credential(challenge)
  local ok, err = pcall(function()
    server:verify_credential_with_expected(credential, {
      amount = '999',
      currency = 'USDC',
      recipient = TEST_RECIPIENT,
    })
  end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.CHARGE_REQUEST_MISMATCH)
end)

helper.test('server emits charge_request_mismatch on currency mismatch', function()
  local server = build_server()
  local challenge = server:charge('0.001')
  local credential = build_credential(challenge)
  local ok, err = pcall(function()
    server:verify_credential_with_expected(credential, {
      amount = '1000',
      currency = 'USDT',
      recipient = TEST_RECIPIENT,
    })
  end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.CHARGE_REQUEST_MISMATCH)
end)

helper.test('server emits charge_request_mismatch on recipient mismatch', function()
  local server = build_server()
  local challenge = server:charge('0.001')
  local credential = build_credential(challenge)
  local ok, err = pcall(function()
    server:verify_credential_with_expected(credential, {
      amount = '1000',
      currency = 'USDC',
      recipient = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ',
    })
  end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.CHARGE_REQUEST_MISMATCH)
end)

helper.test('server emits challenge_verification_failed on HMAC mismatch', function()
  local server = build_server({ secret_key = 'correct-secret' })
  local challenge = server:charge('0.001')
  -- Re-issue the challenge under the wrong secret; the HMAC check rebuilds
  -- the id from echoed fields and rejects.
  local echo = challenge:to_echo()
  resign_echo(echo, 'wrong-secret')
  local credential = mpp.NewPaymentCredential(echo, {
    type = 'signature',
    signature = 'stub',
  })
  local ok, err = pcall(function() server:verify_credential(credential) end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.CHALLENGE_VERIFICATION_FAILED)
end)

helper.test('server emits challenge_expired on a stale challenge', function()
  local server = build_server()
  -- Issue with an explicit expires in the past so the expiry check fires
  -- after the HMAC verify (which still passes against the stamped expires
  -- because that field is included in the HMAC input).
  local challenge = server:charge_with_options('0.001', {
    expires = '2020-01-01T00:00:00Z',
  })
  local credential = build_credential(challenge)
  local ok, err = pcall(function()
    server:verify_credential(credential, 1770000000)
  end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.CHALLENGE_EXPIRED)
end)

helper.test('server emits challenge_route_mismatch on tampered realm', function()
  local server = build_server({ realm = 'Server Realm' })
  local challenge = server:charge('0.001')
  -- Mutate the echoed realm and re-sign so Tier-1 HMAC passes; the Tier-2
  -- pinned realm check then bites with CHALLENGE_ROUTE_MISMATCH.
  local echo = challenge:to_echo()
  echo.realm = 'Attacker Realm'
  resign_echo(echo, TEST_SECRET)
  local credential = mpp.NewPaymentCredential(echo, {
    type = 'signature',
    signature = 'stub',
  })
  local ok, err = pcall(function() server:verify_credential(credential) end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.CHALLENGE_ROUTE_MISMATCH)
end)

helper.test('server emits challenge_route_mismatch on currency tier-2 backstop', function()
  local server = build_server({ currency = 'USDC' })
  -- Issue a challenge against a separate server configured for USDT,
  -- then verify it against the USDC server. Both servers share TEST_SECRET
  -- so the HMAC verifies; the Tier-2 currency pinned field then rejects.
  local other = build_server({ currency = 'USDT' })
  local challenge = other:charge('0.001')
  local credential = build_credential(challenge)
  local ok, err = pcall(function() server:verify_credential(credential) end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.CHALLENGE_ROUTE_MISMATCH)
end)

helper.test('server emits payment_invalid on unsupported payload type', function()
  local server = build_server()
  local challenge = server:charge('0.001')
  -- Synthesize a credential payload whose `type` is neither 'transaction'
  -- nor 'signature'. The payload-shape check at the end of
  -- _verify_challenge_and_decode rejects this with PAYMENT_INVALID.
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), { type = 'unknown' })
  local ok, err = pcall(function() server:verify_credential(credential) end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.PAYMENT_INVALID)
end)

helper.test('server emits signature_consumed on replay rejection', function()
  local server = build_server({
    verify_payment = function()
      return { reference = 'replay-target' }
    end,
  })
  local first_challenge = server:charge('0.001')
  local first_cred = build_credential(first_challenge)
  -- First settlement should succeed (we ignore the receipt body, just need
  -- the replay store to record the reference key).
  server:verify_credential(first_cred)

  -- Second attempt with a fresh challenge but the SAME reference returned
  -- by verify_payment lands the replay store's same key.
  local second_challenge = server:charge('0.001')
  local second_cred = build_credential(second_challenge)
  local ok, err = pcall(function() server:verify_credential(second_cred) end)
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.SIGNATURE_CONSUMED)
end)

helper.test('network_check.assert_network_blockhash raises wrong_network', function()
  local ok, err = pcall(network_check.assert_network_blockhash, 'mainnet-beta',
    'SURFNETxSAFEHASH1234567890abcdefABCDEF')
  helper.assert_equal(ok, false)
  helper.assert_equal(code_of(err), error_codes.WRONG_NETWORK)
end)
