--[[
P1 errors module: all canonical error strings carry the pay_kit:
prefix and are stable constants apps can compare against.
]]

local helper = require('tests.test_helper')
local errors = require('pay_kit.errors')

helper.test('every exported error string carries the pay_kit prefix', function()
  for name, value in pairs(errors) do
    helper.assert_equal(type(value), 'string', 'errors.' .. name .. ' must be a string')
    helper.assert_true(value:find('^pay_kit: '), 'errors.' .. name .. ' missing prefix')
  end
end)

helper.test('specific canonical codes are exported', function()
  helper.assert_equal(errors.PAYMENT_REQUIRED, 'pay_kit: payment required')
  helper.assert_equal(errors.DEMO_SIGNER_ON_MAINNET, 'pay_kit: demo signer cannot be used on solana_mainnet')
  helper.assert_equal(errors.SIGNATURE_CONSUMED, 'pay_kit: signature already consumed')
  helper.assert_equal(errors.WRONG_NETWORK, 'pay_kit: wrong network')
  helper.assert_equal(errors.CHARGE_REQUEST_MISMATCH, 'pay_kit: charge request mismatch')
end)
