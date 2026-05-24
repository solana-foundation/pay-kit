-- Coverage for mpp.protocol.intents.charge helpers.
local charge = require('mpp.protocol.intents.charge')
local helpers = require('tests.test_helper')

local function assert_throws(fn, pattern)
  local ok, err = pcall(fn)
  if ok then error('expected function to raise') end
  if pattern and not tostring(err):match(pattern) then
    error('unexpected error: ' .. tostring(err))
  end
end

helpers.test('intents.charge: parse_units errors on empty amount', function()
  assert_throws(function() charge.parse_units('', 6) end, 'required')
end)

helpers.test('intents.charge: parse_units errors on whitespace-only amount', function()
  assert_throws(function() charge.parse_units('   ', 6) end, 'required')
end)

helpers.test('intents.charge: parse_units errors on negative amount', function()
  assert_throws(function() charge.parse_units('-1.5', 6) end, 'negative')
end)

helpers.test('intents.charge: parse_units errors on non-numeric', function()
  assert_throws(function() charge.parse_units('abc', 6) end, 'invalid amount')
end)

helpers.test('intents.charge: parse_units errors when fractional too long', function()
  assert_throws(function() charge.parse_units('1.1234567', 6) end, 'too many decimal')
end)

helpers.test('intents.charge: parse_units whole number', function()
  helpers.assert_equal(charge.parse_units('5', 6), '5000000')
end)

helpers.test('intents.charge: parse_units decimal', function()
  helpers.assert_equal(charge.parse_units('1.5', 6), '1500000')
end)

helpers.test('intents.charge: parse_units zero', function()
  helpers.assert_equal(charge.parse_units('0', 6), '0')
end)

helpers.test('intents.charge: parse_units zero-fractional', function()
  helpers.assert_equal(charge.parse_units('0.0', 2), '0')
end)

helpers.test('intents.charge: parse_units trims whitespace', function()
  helpers.assert_equal(charge.parse_units('  2.5  ', 4), '25000')
end)

helpers.test('intents.charge: parse_amount valid integer', function()
  helpers.assert_equal(charge.parse_amount({ amount = '100' }), '100')
end)

helpers.test('intents.charge: parse_amount errors on decimal', function()
  assert_throws(function() charge.parse_amount({ amount = '1.5' }) end, 'invalid amount')
end)

helpers.test('intents.charge: parse_amount errors on empty', function()
  assert_throws(function() charge.parse_amount({ amount = '' }) end, 'invalid amount')
end)

helpers.test('intents.charge: parse_amount errors on nil', function()
  assert_throws(function() charge.parse_amount({}) end, 'invalid amount')
end)

helpers.test('intents.charge: validate_max_amount passes below', function()
  charge.validate_max_amount({ amount = '500' }, '1000')
end)

helpers.test('intents.charge: validate_max_amount passes at max', function()
  charge.validate_max_amount({ amount = '1000' }, '1000')
end)

helpers.test('intents.charge: validate_max_amount errors above', function()
  assert_throws(function() charge.validate_max_amount({ amount = '2000' }, '1000') end, 'exceeds maximum')
end)

helpers.test('intents.charge: validate_max_amount errors on invalid max', function()
  assert_throws(function() charge.validate_max_amount({ amount = '1' }, 'not_a_number') end, 'invalid max amount')
end)
