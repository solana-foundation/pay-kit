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
