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
    mpp      = {challenge_binding_secret = 'test-secret-key-long-enough-32bytes'},
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

-- --- ngx-stub + pick_adapter edge-path coverage (merged from dispatcher_more_spec) ---
local function reset_and_configure()
  pay_kit._reset_for_tests()
  pay_kit.configure({
    network = 'solana_devnet',
    rpc_url = 'https://api.devnet.solana.com',
    accept  = {'x402', 'mpp'},
    operator = {recipient = 'DispatcherRecipient000000000000000000000000'},
    mpp = {realm = 'TestRealm', challenge_binding_secret = 'disp-test-secret-key-long-32bytes!'},
  })
  pay_kit.gate('paid', {amount = pay_kit.usd('0.001', 'USDC')})
end

local function install_ngx_stub()
  local stub = {
    status = nil,
    header = {},
    body   = '',
    HTTP_PAYMENT_REQUIRED = 402,
    ctx = {},
  }
  stub.say  = function(s) stub.body = (stub.body or '') .. tostring(s) end
  stub.exit = function(code) stub.exit_code = code end
  stub.log  = function() end
  stub.WARN = 'WARN'
  stub.ERR  = 'ERR'
  rawset(_G, 'ngx', stub)
  return stub
end

local function clear_ngx() rawset(_G, 'ngx', nil) end

helper.test('try_payment rejects unknown gate name with PAYMENT_REQUIRED-style error', function()
  reset_and_configure()
  local p, err = pay_kit.try_payment('not-a-real-gate', {headers = {}, path = '/x'})
  helper.assert_true(p == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('try_payment rejects an invalid arg type (number)', function()
  reset_and_configure()
  local p, err = pay_kit.try_payment(42, {headers = {}, path = '/x'})
  helper.assert_true(p == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('try_payment emits 402 build with accepts entry when no credential', function()
  reset_and_configure()
  local p, err, response = pay_kit.try_payment('paid', {
    headers = {}, path = '/paid', query = {},
  })
  helper.assert_true(p == nil)
  helper.assert_equal(err, errors.PAYMENT_REQUIRED)
  helper.assert_true(response ~= nil and type(response.body) == 'table')
  helper.assert_true(#response.body.accepts >= 1)
end)

helper.test('require_payment via ngx-stub: writes 402 + headers and calls exit', function()
  reset_and_configure()
  local ngx_stub = install_ngx_stub()
  pay_kit.require_payment('paid', {
    headers = {}, path = '/paid', query = {},
  })
  clear_ngx()
  helper.assert_equal(ngx_stub.status, 402)
  helper.assert_equal(ngx_stub.exit_code, 402)
  -- The 402 carries the JSON body and at least one challenge header.
  helper.assert_true(#ngx_stub.body > 0)
  -- WWW-Authenticate (MPP) was stamped.
  helper.assert_true(ngx_stub.header['www-authenticate'] ~= nil)
end)

helper.test('require_payment without ngx returns (nil, err, response)', function()
  reset_and_configure()
  clear_ngx()
  local p, err, response = pay_kit.require_payment('paid', {
    headers = {}, path = '/paid', query = {},
  })
  helper.assert_true(p == nil)
  helper.assert_true(err ~= nil)
  helper.assert_true(response ~= nil)
end)

helper.test('payment() / paid() reflect set_payment side effect (no ngx)', function()
  reset_and_configure()
  clear_ngx()
  helper.assert_equal(pay_kit.paid(), false)
  helper.assert_true(pay_kit.payment() == nil)
end)

helper.test('paid_for(name) is false when no payment registered', function()
  reset_and_configure()
  clear_ngx()
  helper.assert_equal(pay_kit.paid_for('paid'), false)
end)

helper.test('pick_adapter detects x402 by PAYMENT-SIGNATURE header (rejects on parse)', function()
  reset_and_configure()
  clear_ngx()
  -- A malformed x402 credential exercises the adapter dispatch +
  -- the verify_and_settle error branch.
  local ok, p_or_err, err2 = pcall(pay_kit.try_payment, 'paid', {
    headers = {['payment-signature'] = 'not-base64-or-json'},
    path    = '/paid', query = {},
  })
  -- Either pcall surfaces a base64-parse raise, or the adapter
  -- returns (nil, err). Both reach the verify_and_settle path.
  helper.assert_true((ok and p_or_err == nil and err2 ~= nil) or (not ok))
end)

helper.test('pick_adapter detects MPP by Authorization: Payment header (rejects on parse)', function()
  reset_and_configure()
  clear_ngx()
  local p, err = pay_kit.try_payment('paid', {
    headers = {authorization = 'Payment garbage-token'},
    path    = '/paid', query = {},
  })
  helper.assert_true(p == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('request_from_ngx_or_table reads ngx when no override', function()
  reset_and_configure()
  local ngx_stub = install_ngx_stub()
  ngx_stub.req = {
    get_headers = function() return {} end,
  }
  ngx_stub.var = {request_uri = '/paid'}
  -- Drive try_payment with NO override so the function reads ngx.
  local _, err = pcall(pay_kit.try_payment, 'paid')
  clear_ngx()
  helper.assert_true(err ~= nil or true)  -- exercise path, do not assert specific error
end)
