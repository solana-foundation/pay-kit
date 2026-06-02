local t = require('tests.test_helper')
local mpp = require('tests._mpp')

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

-- RFC 8785 (canonical JSON) and RFC 3339 (expires) tests moved to
-- json_canonical_rfc8785_spec.lua and expires_rfc3339_spec.lua per
-- PR #102 review (inline comment 3298060956).

t.test('parse_www_authenticate_all single Payment scheme', function()
  local h = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30"'
  local results = mpp.ParseWWWAuthenticateAll(h)
  t.assert_equal(#results, 1)
  t.assert_equal(results[1].id, 'a')
end)

t.test('parse_www_authenticate_all Payment followed by Bearer', function()
  local h = 'Payment id="a", realm="r", method="solana", intent="charge", request="e30", '
         .. 'Bearer realm="oauth"'
  local results = mpp.ParseWWWAuthenticateAll(h)
  t.assert_equal(#results, 1)
  t.assert_equal(results[1].id, 'a')
end)

t.test('parse_www_authenticate_all Bearer followed by Payment', function()
  local h = 'Bearer realm="oauth", '
         .. 'Payment id="a", realm="r", method="solana", intent="charge", request="e30"'
  local results = mpp.ParseWWWAuthenticateAll(h)
  t.assert_equal(#results, 1)
  t.assert_equal(results[1].id, 'a')
end)

t.test('parse_www_authenticate_all interleaved schemes', function()
  local h = 'Bearer realm="oauth", '
         .. 'Payment id="a", realm="r", method="solana", intent="charge", request="e30", '
         .. 'Basic realm="basic", '
         .. 'Payment id="b", realm="r", method="solana", intent="charge", request="e30"'
  local results = mpp.ParseWWWAuthenticateAll(h)
  t.assert_equal(#results, 2)
  t.assert_equal(results[1].id, 'a')
  t.assert_equal(results[2].id, 'b')
end)

t.test('parse_www_authenticate_all skips malformed challenge and returns valid siblings', function()
  -- First challenge has invalid base64url in request; second is valid. Should yield one challenge.
  local header = 'Payment id="bad", realm="r", method="solana", intent="charge", request="!!!", '
              .. 'Payment id="ok", realm="r", method="solana", intent="charge", request="e30"'
  local results = mpp.ParseWWWAuthenticateAll(header)
  t.assert_equal(#results, 1)
  t.assert_equal(results[1].id, 'ok')
end)


-- Wire-type + MPP error helper edge cases (merged from library_coverage_spec).

do
  local types = require('pay_kit.protocol.core.types')
  local mpp_error = require('pay_kit.protocols.mpp.error')

  t.test('types Base64URLJSON:is_empty reports empty raw', function()
    t.assert_equal(types.new_base64url_json_raw(''):is_empty(), true)
    t.assert_equal(types.new_base64url_json_raw(nil):is_empty(), true)
    t.assert_equal(types.new_base64url_json_raw('eyJhIjoxfQ'):is_empty(), false)
  end)

  t.test('types Base64URLJSON:decode surfaces base64 error', function()
    local value, err = types.new_base64url_json_raw('!!!not-base64!!!'):decode()
    t.assert_equal(value, nil)
    t.assert_true(err ~= nil)
  end)

  t.test('types Base64URLJSON:decode surfaces JSON error', function()
    local raw = types.base64url_encode('not-json{')
    local value, err = types.new_base64url_json_raw(raw):decode()
    t.assert_equal(value, nil)
    t.assert_true(err ~= nil)
  end)

  t.test('types.is_valid_method rejects non-strings and empty strings', function()
    t.assert_equal(types.is_valid_method(nil), false)
    t.assert_equal(types.is_valid_method(''), false)
    t.assert_equal(types.is_valid_method(123), false)
    t.assert_equal(types.is_valid_method('charge'), true)
    t.assert_equal(types.is_valid_method('Charge'), false)
  end)

  t.test('mpp.error.new returns a table with code, message, details', function()
    local err = mpp_error.new('bad', 'oops', { hint = 'try again' })
    t.assert_equal(err.code, 'bad')
    t.assert_equal(err.message, 'oops')
    t.assert_equal(err.details.hint, 'try again')
  end)

  t.test('mpp.error.raise throws a table error', function()
    local ok, err = pcall(function() mpp_error.raise('boom', 'kaput', nil) end)
    t.assert_true(not ok)
    t.assert_equal(type(err), 'table')
    t.assert_equal(err.code, 'boom')
    t.assert_equal(err.message, 'kaput')
  end)
end
