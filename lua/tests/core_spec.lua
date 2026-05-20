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

t.test('parse authorization rejects missing payment scheme', function()
  t.assert_error(function()
    mpp.ParseAuthorization('Bearer abc')
  end, 'Payment')
end)

t.test('parse authorization rejects malformed credential JSON', function()
  t.assert_error(function()
    mpp.ParseAuthorization('Payment bm90LWpzb24')
  end, 'invalid credential JSON')
end)

t.test('parse www-authenticate rejects missing challenge request', function()
  t.assert_error(function()
    mpp.ParseWWWAuthenticate('Payment id="id", realm="realm", method="solana", intent="charge"')
  end, 'request')
end)
