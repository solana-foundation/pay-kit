local t = require('tests.test_helper')
local mpp = require('mpp')

t.test('www-authenticate round trip', function()
  local request = mpp.NewBase64URLJSONValue({ amount = '1000', currency = 'sol' })
  local challenge = mpp.NewChallengeWithSecretFull(
    'secret',
    'realm',
    mpp.NewMethodName('solana'),
    mpp.NewIntentName('charge'),
    request,
    '2030-01-01T00:00:00Z',
    nil,
    'desc',
    nil
  )
  local header = mpp.FormatWWWAuthenticate(challenge)
  local parsed = mpp.ParseWWWAuthenticate(header)
  t.assert_equal(parsed.id, challenge.id)
  t.assert_equal(parsed.realm, challenge.realm)
  t.assert_equal(parsed.request:raw(), challenge.request:raw())
end)

t.test('authorization round trip', function()
  local request = mpp.NewBase64URLJSONValue({ amount = '1000' })
  local challenge = mpp.NewChallengeWithSecret('secret', 'realm', mpp.NewMethodName('solana'), mpp.NewIntentName('charge'), request)
  local credential = mpp.NewPaymentCredential(challenge:to_echo(), { type = 'transaction', transaction = 'abc' })
  local header = mpp.FormatAuthorization(credential)
  local parsed = mpp.ParseAuthorization(header)
  t.assert_equal(parsed.challenge.id, challenge.id)
  t.assert_equal(parsed.payload.type, 'transaction')
end)

t.test('receipt round trip', function()
  local header = mpp.FormatReceipt({
    status = mpp.ReceiptStatusSuccess,
    method = 'solana',
    timestamp = '2026-01-01T00:00:00Z',
    reference = 'sig',
    challengeId = 'id',
  })
  local receipt = mpp.ParseReceipt(header)
  t.assert_equal(receipt.reference, 'sig')
end)

t.test('challenge verify and expiry', function()
  local request = mpp.NewBase64URLJSONValue({ amount = '1000' })
  local challenge = mpp.NewChallengeWithSecretFull(
    'secret',
    'realm',
    mpp.NewMethodName('solana'),
    mpp.NewIntentName('charge'),
    request,
    '2020-01-01T00:00:00Z',
    nil,
    nil,
    nil
  )
  t.assert_true(challenge:verify('secret'))
  t.assert_true(not challenge:verify('wrong'))
  t.assert_true(challenge:is_expired(1893456000))
end)

t.test('parse units converts decimal amount', function()
  t.assert_equal(mpp.ParseUnits('1.25', 6), '1250000')
end)

t.test('extract payment scheme ignores other auth parts', function()
  local scheme = mpp.ExtractPaymentScheme('Bearer abc, Payment xyz')
  t.assert_equal(scheme, 'Payment xyz')
end)

t.test('parse_www_authenticate_all parses multi-challenge header (RFC 7235 sec 4.1)', function()
  local header = 'Payment id="a", realm="r1", method="solana", intent="charge", request="e30", '
              .. 'Payment id="b", realm="r2", method="solana", intent="charge", request="e30"'
  local results = mpp.ParseWWWAuthenticateAll(header)
  t.assert_equal(#results, 2)
  t.assert_equal(results[1].id, 'a')
  t.assert_equal(results[2].id, 'b')
end)

t.test('parse_www_authenticate_all ignores Payment inside quoted realm', function()
  local header = 'Payment id="a", realm="api, Payment realm", method="solana", intent="charge", request="e30", '
              .. 'Payment id="b", realm="r2", method="solana", intent="charge", request="e30"'
  local results = mpp.ParseWWWAuthenticateAll(header)
  t.assert_equal(#results, 2)
  t.assert_equal(results[1].realm, 'api, Payment realm')
  t.assert_equal(results[2].id, 'b')
end)

t.test('canonical JSON sorts keys by UTF-16 code units (RFC 8785 sec 3.2.3)', function()
  local json = require('mpp.util.json')
  -- 'é' (U+00E9) > 'f' (U+0066) in UTF-16 code-unit order, so 'f' sorts first.
  local encoded = json.encode({ ['é'] = 1, f = 2 })
  t.assert_equal(encoded, '{"f":2,"\xC3\xA9":1}')
end)

t.test('canonical JSON serializes numbers per ES6 ToString', function()
  local json = require('mpp.util.json')
  t.assert_equal(json.encode(1e21), '1e+21')
  t.assert_equal(json.encode(0.1), '0.1')
  t.assert_equal(json.encode(-0.0), '0')
  t.assert_equal(json.encode(42), '42')
end)

t.test('canonical JSON rejects lone surrogates', function()
  local json = require('mpp.util.json')
  local lone = string.char(0xED, 0xA0, 0xB4)
  local ok = pcall(json.encode, { k = lone })
  t.assert_true(not ok)
end)

t.test('expires parser is strict RFC 3339', function()
  local expires = require('mpp.expires')
  t.assert_true(expires.parse_rfc3339('2099-01-01T00:00:00Z') ~= nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01T00:00:00+00:00') ~= nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01T00:00:00.123Z') ~= nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01t00:00:00z') ~= nil)
  t.assert_true(expires.parse_rfc3339('tomorrow') == nil)
  t.assert_true(expires.parse_rfc3339('10000-01-01T00:00:00Z') == nil)
  t.assert_true(expires.parse_rfc3339('2099-02-30T00:00:00Z') == nil)
  t.assert_true(expires.parse_rfc3339('2099-13-01T00:00:00Z') == nil)
  t.assert_true(expires.parse_rfc3339('2099-01-01T24:00:00Z') == nil)
end)

t.test('parse_www_authenticate_all skips malformed challenge and returns valid siblings', function()
  -- First challenge has invalid base64url in request; second is valid. Should yield one challenge.
  local header = 'Payment id="bad", realm="r", method="solana", intent="charge", request="!!!", '
              .. 'Payment id="ok", realm="r", method="solana", intent="charge", request="e30"'
  local results = mpp.ParseWWWAuthenticateAll(header)
  t.assert_equal(#results, 1)
  t.assert_equal(results[1].id, 'ok')
end)

t.test('canonical JSON ES6 ToString boundary cases', function()
  local json = require('mpp.util.json')
  t.assert_equal(json.encode(1e-6), '0.000001')
  t.assert_equal(json.encode(1e-7), '1e-7')
  t.assert_equal(json.encode(1e20), '100000000000000000000')
  t.assert_equal(json.encode(0.1 + 0.2), '0.30000000000000004')
end)

t.test('canonical JSON shortest round-trip needs 16 significant digits', function()
  -- Codex P2 on PR #102. Previously %.15g-then-%.17g returned "333333333.33333331"
  -- because %.15g does not round-trip; the correct ES6 ToString is "333333333.3333333"
  -- which requires exactly 16 significant digits.
  local json = require('mpp.util.json')
  t.assert_equal(json.encode(333333333.33333329), '333333333.3333333')
end)

t.test('expires parser rejects bare fractional dot (RFC 3339 sec 5.6)', function()
  -- Codex P3 on PR #102. The dot must be followed by at least one digit.
  local expires = require('mpp.expires')
  t.assert_true(expires.parse_rfc3339('2026-01-01T00:00:00.Z') == nil)
  t.assert_true(expires.parse_rfc3339('2026-01-01T00:00:00.+00:00') == nil)
  -- A normal fractional value still parses.
  t.assert_true(expires.parse_rfc3339('2026-01-01T00:00:00.5Z') ~= nil)
end)
