--[[
P6 dispatcher. Pure-Lua mode: require_payment hands back
(payment, err, response) when no payment header is present (since
there is no ngx.exit to call).
]]

local helper = require('tests.test_helper')
local pay_kit = require('pay_kit')
local errors  = require('pay_kit.errors')

local SELLER = 'SeLLeRWaLLeT111111111111111111111111111111'

local function setup()
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({
    network  = 'solana_devnet',
    operator = {recipient = SELLER},
    mpp      = {challenge_binding_secret = 'test-secret'},
  }))
end

helper.test('try_payment on unknown gate returns gate-not-found', function()
  setup()
  local _, err = pay_kit.try_payment('not_registered', {headers = {}, path = '/x'})
  helper.assert_equal(err, errors.GATE_NOT_FOUND)
end)

helper.test('try_payment on unpaid request returns 402 envelope', function()
  setup()
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local payment, err, response = pay_kit.try_payment('report', {headers = {}, path = '/report'})
  helper.assert_equal(payment, nil)
  helper.assert_equal(err, errors.PAYMENT_REQUIRED)
  helper.assert_true(response ~= nil and response.body ~= nil)
  helper.assert_equal(response.body.error, 'payment_required')
  helper.assert_equal(response.body.resource, '/report')
  helper.assert_true(#response.body.accepts >= 1)
end)

helper.test('require_payment in pure-Lua mode mirrors try_payment shape', function()
  setup()
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local payment, err, response = pay_kit.require_payment('report', {headers = {}, path = '/report'})
  helper.assert_equal(payment, nil)
  helper.assert_true(err == errors.PAYMENT_REQUIRED)
  helper.assert_true(response ~= nil)
end)

helper.test('payment()/paid()/paid_for() default to nil/false when unpaid', function()
  setup()
  helper.assert_equal(pay_kit.payment(), nil)
  helper.assert_equal(pay_kit.paid(), false)
  helper.assert_equal(pay_kit.paid_for('report'), false)
end)

helper.test('inline gate via require_payment table form emits 402 too', function()
  setup()
  local _, err, response = pay_kit.require_payment(
    {amount = assert(pay_kit.usd('0.25')), description = 'One-off'},
    {headers = {}, path = '/inline'}
  )
  helper.assert_equal(err, errors.PAYMENT_REQUIRED)
  helper.assert_equal(response.body.resource, '/inline')
end)

helper.test('dispatcher refuses when configure() was not called', function()
  pay_kit._reset_for_tests()
  local _, err = pay_kit.try_payment('whatever')
  helper.assert_true(err and err:find('configure', 1, true), err)
end)
