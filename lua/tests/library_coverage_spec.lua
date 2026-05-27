-- Additional unit tests targeting previously-uncovered code branches in the
-- Lua SDK library modules. These cover error helpers, charge intent parsing,
-- network blockhash assertion, type wrappers, store deletion, and RFC3339
-- edge cases that the broader integration specs do not exercise.

local helper = require('tests.test_helper')
local test = helper.test
local assert_equal = helper.assert_equal
local assert_true = helper.assert_true
local assert_error = helper.assert_error

local mpp_error = require('pay_kit.protocols.mpp.error')
local charge = require('pay_kit.protocols.mpp.charge')
local network_check = require('pay_kit.protocols.mpp.server.network_check')
local types = require('pay_kit.protocol.core.types')
local store = require('pay_kit.protocols.mpp.store')
local expires = require('pay_kit.protocols.mpp.expires')

-- mpp.error -------------------------------------------------------------------

test('mpp.error.new returns table with code, message, details', function()
  local err = mpp_error.new('bad', 'oops', { hint = 'try again' })
  assert_equal(err.code, 'bad')
  assert_equal(err.message, 'oops')
  assert_equal(err.details.hint, 'try again')
end)

test('mpp.error.raise throws a table error', function()
  local ok, err = pcall(function()
    mpp_error.raise('boom', 'kaput', nil)
  end)
  assert_true(not ok, 'expected raise to throw')
  assert_equal(type(err), 'table')
  assert_equal(err.code, 'boom')
  assert_equal(err.message, 'kaput')
end)

-- pay_kit.protocols.mpp.charge -------------------------------------------------

test('charge.parse_units rejects empty amount', function()
  assert_error(function() charge.parse_units('', 6) end, 'amount is required')
  assert_error(function() charge.parse_units(nil, 6) end, 'amount is required')
  assert_error(function() charge.parse_units('   ', 6) end, 'amount is required')
end)

test('charge.parse_units rejects negative amounts', function()
  assert_error(function() charge.parse_units('-1.0', 6) end, 'cannot be negative')
end)

test('charge.parse_units rejects malformed amount', function()
  assert_error(function() charge.parse_units('abc', 6) end, 'invalid amount')
  assert_error(function() charge.parse_units('1.2.3', 6) end, 'invalid amount')
end)

test('charge.parse_units rejects too many decimal places', function()
  assert_error(function() charge.parse_units('1.1234567', 6) end, 'too many decimal places')
end)

test('charge.parse_units returns 0 for zero', function()
  assert_equal(charge.parse_units('0', 6), '0')
  assert_equal(charge.parse_units('0.000000', 6), '0')
end)

test('charge.parse_amount accepts integer strings', function()
  assert_equal(charge.parse_amount({ amount = '12345' }), '12345')
end)

test('charge.parse_amount rejects non-integer', function()
  assert_error(function() charge.parse_amount({ amount = '1.5' }) end, 'invalid amount')
  assert_error(function() charge.parse_amount({ amount = 'abc' }) end, 'invalid amount')
  assert_error(function() charge.parse_amount({}) end, 'invalid amount')
end)

test('charge.validate_max_amount passes when under cap', function()
  charge.validate_max_amount({ amount = '500' }, '1000')
end)

test('charge.validate_max_amount rejects when above cap', function()
  assert_error(function()
    charge.validate_max_amount({ amount = '2000' }, '1000')
  end, 'exceeds maximum')
end)

test('charge.validate_max_amount rejects non-numeric max', function()
  assert_error(function()
    charge.validate_max_amount({ amount = '100' }, 'not-a-number')
  end, 'invalid max amount')
end)

-- pay_kit.protocols.mpp.server.network_check ----------------------------------------------------

test('network_check.assert_network_blockhash passes for clean blockhash', function()
  network_check.assert_network_blockhash('mainnet', 'NormalBlockhash1234567890')
end)

test('network_check.assert_network_blockhash passes for surfpool on localnet', function()
  network_check.assert_network_blockhash('localnet',
    network_check.SURFPOOL_BLOCKHASH_PREFIX .. 'tail')
end)

test('network_check.assert_network_blockhash raises on surfpool against mainnet', function()
  assert_error(function()
    network_check.assert_network_blockhash('mainnet',
      network_check.SURFPOOL_BLOCKHASH_PREFIX .. 'tail')
  end, 'mainnet')
end)

-- pay_kit.protocol.core.types -----------------------------------------------------

test('types Base64URLJSON:is_empty reports empty raw', function()
  local empty = types.new_base64url_json_raw('')
  assert_equal(empty:is_empty(), true)
  local nil_raw = types.new_base64url_json_raw(nil)
  assert_equal(nil_raw:is_empty(), true)
  local full = types.new_base64url_json_raw('eyJhIjoxfQ')
  assert_equal(full:is_empty(), false)
end)

test('types Base64URLJSON:decode surfaces base64 error', function()
  local bad = types.new_base64url_json_raw('!!!not-base64!!!')
  local value, err = bad:decode()
  assert_equal(value, nil)
  assert_true(err ~= nil, 'expected an error message')
end)

test('types Base64URLJSON:decode surfaces JSON error', function()
  -- Valid base64url for non-JSON garbage `not-json`.
  local raw = types.base64url_encode('not-json{')
  local bad = types.new_base64url_json_raw(raw)
  local value, err = bad:decode()
  assert_equal(value, nil)
  assert_true(err ~= nil, 'expected a JSON error')
end)

test('types.is_valid_method rejects non-strings and empty strings', function()
  assert_equal(types.is_valid_method(nil), false)
  assert_equal(types.is_valid_method(''), false)
  assert_equal(types.is_valid_method(123), false)
  assert_equal(types.is_valid_method('charge'), true)
  assert_equal(types.is_valid_method('Charge'), false)
end)

-- mpp.store -------------------------------------------------------------------

test('store.memory delete removes entries', function()
  local s = store.memory()
  s:put('k', { v = 1 })
  local value, found = s:get('k')
  assert_equal(found, true)
  assert_equal(value.v, 1)
  s:delete('k')
  local _, found_after = s:get('k')
  assert_equal(found_after, false)
end)

-- mpp.expires -----------------------------------------------------------------

test('expires.parse_rfc3339 rejects non-string input', function()
  local value, err = expires.parse_rfc3339(123)
  assert_equal(value, nil)
  assert_true(err ~= nil)
end)

test('expires.parse_rfc3339 rejects fractional seconds longer than 9 digits', function()
  local value, err = expires.parse_rfc3339('2099-01-01T00:00:00.1234567890Z')
  assert_equal(value, nil)
  assert_true(err and err:find('fractional'))
end)

test('expires.parse_rfc3339 rejects years above 9999', function()
  local value, err = expires.parse_rfc3339('10000-01-01T00:00:00Z')
  assert_equal(value, nil)
  assert_true(err ~= nil)
end)

test('expires.parse_rfc3339 rejects out-of-range offset hours', function()
  local value, err = expires.parse_rfc3339('2099-01-01T00:00:00+25:00')
  assert_equal(value, nil)
  assert_true(err and err:find('offset'))
end)

test('expires.parse_rfc3339 accepts April 30 (30-day month)', function()
  -- Exercises the months-with-30-days branch in days_in_month.
  local epoch = expires.parse_rfc3339('2099-04-30T00:00:00Z')
  assert_true(type(epoch) == 'number')
end)

test('expires.is_expired returns true on unparseable input', function()
  -- Passes a non-empty but invalid timestamp so parse_rfc3339 returns nil
  -- and the unparseable branch in is_expired is exercised.
  local result = expires.is_expired('not-a-timestamp', 0)
  assert_equal(result, true)
end)
