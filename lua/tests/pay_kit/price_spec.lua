--[[
P2 usd() price helper. Integer micro-units, string-only amount input,
ordered settlement preference list.
]]

local helper = require('tests.test_helper')
local pay_kit = require('pay_kit')

helper.test('usd parses "0.10" to 100000 micro-units', function()
  local p = assert(pay_kit.usd('0.10'))
  helper.assert_equal(p:units(), 100000)
  helper.assert_equal(p:denomination(), 'USD')
  helper.assert_equal(p:amount_string(), '0.10')
end)

helper.test('usd parses integer-form "1" to 1_000_000', function()
  local p = assert(pay_kit.usd('1'))
  helper.assert_equal(p:units(), 1000000)
end)

helper.test('usd parses "0.000001" (1 micro-unit)', function()
  local p = assert(pay_kit.usd('0.000001'))
  helper.assert_equal(p:units(), 1)
end)

helper.test('usd parses "0" to 0', function()
  local p = assert(pay_kit.usd('0'))
  helper.assert_equal(p:units(), 0)
end)

helper.test('usd rejects float input', function()
  local _, err = pay_kit.usd(0.10)
  helper.assert_true(err and err:find('not a number', 1, true), err)
end)

helper.test('usd rejects empty string', function()
  local _, err = pay_kit.usd('')
  helper.assert_true(err and err:find('empty', 1, true), err)
end)

helper.test('usd rejects negative amounts', function()
  local _, err = pay_kit.usd('-1.00')
  helper.assert_true(err and err:find('non%-negative'), err)
end)

helper.test('usd rejects more than 6 fractional digits', function()
  local _, err = pay_kit.usd('0.0000001')
  helper.assert_true(err and err:find('more than 6 fractional', 1, true), err)
end)

helper.test('usd rejects multiple decimal points', function()
  local _, err = pay_kit.usd('1.2.3')
  helper.assert_true(err and err:find('multiple decimal', 1, true), err)
end)

helper.test('usd rejects non-digit characters', function()
  local _, err = pay_kit.usd('1.0x')
  helper.assert_true(err and err:find('invalid', 1, true), err)
end)

helper.test('usd captures the ordered settlement list', function()
  local p = assert(pay_kit.usd('1.00', 'USDC', 'USDT'))
  local s = p:settlements()
  helper.assert_equal(s[1], 'USDC')
  helper.assert_equal(s[2], 'USDT')
  helper.assert_equal(#s, 2)
  helper.assert_equal(p:primary_coin(), 'USDC')
end)

helper.test('usd deduplicates the settlement list', function()
  local p = assert(pay_kit.usd('1.00', 'USDC', 'USDC', 'USDT'))
  local s = p:settlements()
  helper.assert_equal(#s, 2)
end)

helper.test('usd falls back to {USDC} when no coins passed', function()
  pay_kit._reset_for_tests()
  local p = assert(pay_kit.usd('0.10'))
  helper.assert_equal(p:primary_coin(), 'USDC')
end)

helper.test('usd honours configured stablecoins when no coins passed', function()
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({ stablecoins = { 'USDT' } }))
  local p = assert(pay_kit.usd('0.10'))
  helper.assert_equal(p:primary_coin(), 'USDT')
  pay_kit._reset_for_tests()
end)

-- RULINGS C2/X2: wire amounts are in the asset's atomic units.
helper.test('atomic_units scales 6-decimal units to the asset decimals', function()
  local price = require('pay_kit.internal.price')
  helper.assert_equal(price.atomic_units(1000, 6), '1000')          -- control
  helper.assert_equal(price.atomic_units(1000, 9), '1000000')
  helper.assert_equal(price.atomic_units(1230000, 2), '123')
  helper.assert_error(function() price.atomic_units(1001, 2) end, 'precision')
end)

-- A settlement coin the built-in table does not know needs its decimals.
helper.test('configure requires asset_decimals for an unknown settlement mint', function()
  pay_kit._reset_for_tests()
  local mint = 'KTHzp63RATgvE5RoRRqVbY7hMWntARQ6dPQhMtfY9oA'
  local ok, err = pay_kit.configure({stablecoins = {mint}, preflight = false})
  helper.assert_equal(ok, nil)
  helper.assert_true(err:find('asset_decimals', 1, true), err)
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({stablecoins = {mint}, asset_decimals = {[mint] = 9}, preflight = false,
                            mpp = {challenge_binding_secret = 'price-spec-secret-0123456789abcdef'}}))
  helper.assert_equal(pay_kit.config():decimals_for(mint), 9)
  helper.assert_equal(pay_kit.config():decimals_for('USDC'), 6)
  pay_kit._reset_for_tests()
end)
