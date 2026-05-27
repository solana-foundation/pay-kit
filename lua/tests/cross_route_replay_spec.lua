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
