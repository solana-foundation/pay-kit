local t = require('tests.test_helper')
local mpp = require('tests._mpp')

local TEST_RECIPIENT = '3yGpUKnU5HSVSMxye83YuseTeSQykiS5N4eh6iQn1d2h'
local TEST_SECRET = 'cross-route-replay-test-secret-key'

local function new_server()
  return mpp.server.new({
    recipient = TEST_RECIPIENT,
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = TEST_SECRET,
    store = mpp.store.memory(),
    verify_payment = function(context)
      return { reference = context.payload.signature or context.payload.transaction }
    end,
  })
end

-- Recompute the HMAC ID after a test mutates one of the echoed fields.
local function resign_echo(echo)
  echo.id = mpp.ComputeChallengeID(
    TEST_SECRET,
    echo.realm,
    echo.method,
    echo.intent,
    echo.request:raw(),
    echo.expires or '',
    echo.digest or '',
    (echo.opaque and echo.opaque:raw()) or nil
  )
end

local function bogus_signature_credential(echo)
  return mpp.NewPaymentCredential(echo, {
    type = 'signature',
    signature = '5jKh25biPsnrmLWXXuqKNH2Q67Q4UmVVx8Gf2wrS6VoCeyfGE9wKikjY7Q1GQQgmpQ3xy7wJX5U1rcz82q4R8N',
  })
end

-- ── Tier-2 pinned-field tests ──────────────────────────────────────────────

t.test('tier2 rejects tampered realm', function()
  local server = new_server()
  local challenge = server:charge('0.10')
  local echo = challenge:to_echo()
  echo.realm = 'Attacker Realm'
  resign_echo(echo)
  t.assert_error(function()
    server:verify_credential(bogus_signature_credential(echo), 1770000000)
  end, 'realm')
end)

t.test('tier2 rejects tampered method', function()
  local server = new_server()
  local challenge = server:charge('0.10')
  local echo = challenge:to_echo()
  echo.method = 'stripe'
  resign_echo(echo)
  t.assert_error(function()
    server:verify_credential(bogus_signature_credential(echo), 1770000000)
  end, 'method')
end)

t.test('tier2 rejects non-charge intent', function()
  local server = new_server()
  local challenge = server:charge('0.10')
  local echo = challenge:to_echo()
  echo.intent = 'session'
  resign_echo(echo)
  t.assert_error(function()
    server:verify_credential(bogus_signature_credential(echo), 1770000000)
  end, 'intent')
end)

t.test('tier2 rejects tampered currency', function()
  local server = new_server()
  local challenge = server:charge('0.10')
  local request = challenge.request:decode()
  request.currency = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
  local echo = challenge:to_echo()
  echo.request = mpp.NewBase64URLJSONValue(request)
  resign_echo(echo)
  t.assert_error(function()
    server:verify_credential(bogus_signature_credential(echo), 1770000000)
  end, 'currency')
end)

t.test('tier2 rejects tampered recipient', function()
  local server = new_server()
  local challenge = server:charge('0.10')
  local request = challenge.request:decode()
  request.recipient = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ'
  local echo = challenge:to_echo()
  echo.request = mpp.NewBase64URLJSONValue(request)
  resign_echo(echo)
  t.assert_error(function()
    server:verify_credential(bogus_signature_credential(echo), 1770000000)
  end, 'recipient')
end)

-- ── verify_credential_with_expected tests ─────────────────────────────────

t.test('with_expected rejects amount mismatch', function()
  local server = new_server()
  local cheap = server:charge('0.001')
  local credential = bogus_signature_credential(cheap:to_echo())

  local expensive = server:charge('1')
  local expected = expensive.request:decode()

  t.assert_error(function()
    server:verify_credential_with_expected(credential, expected, 1770000000)
  end, 'amount')
end)

t.test('with_expected accepts matching route', function()
  -- When credential matches route, the binding/Tier-2 layer must not reject.
  -- Settlement runs (the user's verify_payment callback succeeds with our
  -- bogus signature), so this also confirms the happy path still works.
  local server = new_server()
  local challenge = server:charge('0.10')
  local credential = bogus_signature_credential(challenge:to_echo())
  local expected = challenge.request:decode()

  local receipt = server:verify_credential_with_expected(credential, expected, 1770000000)
  t.assert_equal(receipt.status, 'success')
  t.assert_equal(receipt.challengeId, challenge.id)
end)

-- ── LUA-6 route binding: methodDetails + externalId must be bound ──────────

-- Issue a challenge with a given splits/fee-payer shape, then attempt to
-- settle it against a route whose expected request carries a DIFFERENT
-- shape. Pre-fix this passed (only amount/currency/recipient were
-- compared); post-fix it must raise charge_request_mismatch.

t.test('with_expected rejects mismatched splits in methodDetails', function()
  local server = new_server()
  -- Credential issued for a route that splits 100 base-units to a fee
  -- recipient.
  local challenge = server:charge_with_options('1', {
    splits = {{recipient = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ', amount = '100'}},
  })
  local credential = bogus_signature_credential(challenge:to_echo())

  -- Route expects the SAME price/recipient but a different split amount.
  local expected = challenge.request:decode()
  expected.methodDetails.splits = {
    {recipient = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ', amount = '500'},
  }

  t.assert_error(function()
    server:verify_credential_with_expected(credential, expected, 1770000000)
  end, 'method details')
end)

-- Pull-mode (transaction-payload) credential so the push-mode + fee-payer
-- guard does not fire first; this isolates the methodDetails-binding
-- rejection on feePayerKey.
local function bogus_transaction_credential(echo)
  return mpp.NewPaymentCredential(echo, {
    type = 'transaction',
    transaction = 'ZmFrZS10eC1iYXNlNjQ=',
  })
end

t.test('with_expected rejects mismatched feePayerKey in methodDetails', function()
  local server = new_server()
  local challenge = server:charge_with_options('1', {
    fee_payer = true,
    fee_payer_key = 'FeePayerAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  })
  local credential = bogus_transaction_credential(challenge:to_echo())

  local expected = challenge.request:decode()
  expected.methodDetails.feePayerKey = 'AttackerBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'

  t.assert_error(function()
    server:verify_credential_with_expected(credential, expected, 1770000000)
  end, 'method details')
end)

t.test('with_expected rejects mismatched externalId', function()
  local server = new_server()
  local challenge = server:charge_with_options('1', {external_id = 'order-123'})
  local credential = bogus_signature_credential(challenge:to_echo())

  local expected = challenge.request:decode()
  expected.externalId = 'order-999'

  t.assert_error(function()
    server:verify_credential_with_expected(credential, expected, 1770000000)
  end, 'externalId')
end)

t.test('with_expected ignores recentBlockhash drift in methodDetails', function()
  -- recentBlockhash is a per-request freshness field, not a route binding;
  -- a credential carrying a blockhash must still settle against a route
  -- whose expected request omits / differs on it.
  local server = new_server()
  local challenge = server:charge_with_options('1', {
    recent_blockhash = 'BlockhashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  })
  local credential = bogus_signature_credential(challenge:to_echo())

  local expected = challenge.request:decode()
  expected.methodDetails.recentBlockhash = 'BlockhashZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ'

  local receipt = server:verify_credential_with_expected(credential, expected, 1770000000)
  t.assert_equal(receipt.status, 'success')
end)

t.test('with_expected settles from the route expected, not the credential', function()
  -- A credential whose externalId/methodDetails MATCH the route (so binding
  -- passes) still settles using the route's `expected` values. Capture the
  -- request handed to verify_payment and assert it carries the route
  -- externalId, proving settlement reads `expected`, not the credential.
  local captured
  local server = mpp.server.new({
    recipient = TEST_RECIPIENT,
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = TEST_SECRET,
    store = mpp.store.memory(),
    verify_payment = function(context)
      captured = context.request
      return { reference = context.payload.signature or context.payload.transaction }
    end,
  })
  local challenge = server:charge_with_options('1', {external_id = 'order-77'})
  local credential = bogus_signature_credential(challenge:to_echo())
  local expected = challenge.request:decode()

  server:verify_credential_with_expected(credential, expected, 1770000000)
  t.assert_true(captured ~= nil, 'verify_payment must be called')
  t.assert_equal(captured.externalId, 'order-77')
  t.assert_equal(captured.amount, expected.amount)
end)

-- ── Regression: minimal expected form must not be rejected ─────────────────

-- The documented minimal expected request {amount, currency, recipient}
-- (methodDetails / externalId omitted) is what the nginx / simple-server /
-- Kong examples pass. A prior round-1 change made the methodDetails compare
-- UNCONDITIONAL, so the minimal form (expected.methodDetails == nil)
-- canonicalized to `{}` and never matched a credential carrying any
-- methodDetails, rejecting every example call with "method details
-- mismatch". This test fails pre-fix and passes post-fix.
t.test('with_expected accepts the minimal {amount,currency,recipient} form', function()
  local server = new_server()
  -- Credential carries a real methodDetails shape (splits + decimals), just
  -- like a wire challenge would.
  local challenge = server:charge_with_options('0.25', {
    splits = {{recipient = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ', amount = '50'}},
  })
  local credential = bogus_signature_credential(challenge:to_echo())
  local request = challenge.request:decode()

  local receipt = server:verify_credential_with_expected(credential, {
    amount = request.amount,
    currency = request.currency,
    recipient = request.recipient,
  }, 1770000000)
  t.assert_equal(receipt.status, 'success')
  t.assert_equal(receipt.challengeId, challenge.id)
end)

-- With the minimal form the credential's own methodDetails / externalId
-- become the settlement defaults, so the verifier still receives the full
-- on-chain shape (it is not silently dropped to `{}`).
t.test('with_expected minimal form carries credential methodDetails into settlement', function()
  local captured
  local server = mpp.server.new({
    recipient = TEST_RECIPIENT,
    currency = 'USDC',
    decimals = 6,
    network = 'localnet',
    secret_key = TEST_SECRET,
    store = mpp.store.memory(),
    verify_payment = function(context)
      captured = context.request
      return { reference = context.payload.signature or context.payload.transaction }
    end,
  })
  local challenge = server:charge_with_options('1', {
    external_id = 'order-minimal',
    splits = {{recipient = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ', amount = '100'}},
  })
  local credential = bogus_signature_credential(challenge:to_echo())
  local request = challenge.request:decode()

  server:verify_credential_with_expected(credential, {
    amount = request.amount,
    currency = request.currency,
    recipient = request.recipient,
  }, 1770000000)
  t.assert_true(captured ~= nil, 'verify_payment must be called')
  -- externalId falls back to the credential's value when expected omits it.
  t.assert_equal(captured.externalId, 'order-minimal')
  -- methodDetails.splits flowed through from the credential, not dropped.
  t.assert_true(type(captured.methodDetails) == 'table', 'methodDetails carried')
  t.assert_true(captured.methodDetails.splits ~= nil, 'splits carried into settlement')
end)
