--[[
P2 Operator value object - nil-as-no-opinion + recipient default-to-
signer-pubkey + strict signer / fee_payer validation.
]]

local helper = require('tests.test_helper')
local operator = require('pay_kit.internal.operator')
local signer_mod = require('pay_kit.signer')
local demo_signer = require('pay_kit.signer.demo')

local function fresh_signer()
  local bytes = {}
  for i = 1, 64 do bytes[i] = ((i + 17) % 256) end
  return assert(signer_mod.bytes(bytes))
end

helper.test('operator.new() defaults to demo signer + fee_payer=true', function()
  demo_signer.reset_for_tests()
  local op = assert(operator.new())
  helper.assert_equal(op:signer():pubkey(), demo_signer.PUBKEY)
  helper.assert_equal(op:signer():demo(), true)
  helper.assert_equal(op:fee_payer(), true)
  helper.assert_equal(op:recipient(), nil)
  helper.assert_equal(op:effective_recipient(), demo_signer.PUBKEY)
end)

helper.test('explicit recipient overrides the signer-pubkey default', function()
  demo_signer.reset_for_tests()
  local op = assert(operator.new({recipient = 'ExplicitWallet111'}))
  helper.assert_equal(op:recipient(), 'ExplicitWallet111')
  helper.assert_equal(op:effective_recipient(), 'ExplicitWallet111')
end)

helper.test('explicit signer takes precedence over the demo', function()
  local sgn = fresh_signer()
  local op = assert(operator.new({signer = sgn}))
  helper.assert_equal(op:signer():demo(), false)
  helper.assert_equal(op:effective_recipient(), sgn:pubkey())
end)

helper.test('fee_payer=false is honoured', function()
  local op = assert(operator.new({fee_payer = false}))
  helper.assert_equal(op:fee_payer(), false)
end)

helper.test('recipient must be a string', function()
  local _, err = operator.new({recipient = 42})
  helper.assert_true(err and err:find('recipient', 1, true), err)
end)

helper.test('signer must satisfy the duck-type', function()
  local _, err = operator.new({signer = {}})
  helper.assert_true(err and err:find('signer', 1, true), err)
end)

helper.test('fee_payer must be strict boolean', function()
  for _, bad in ipairs({0, 1, 'true', 'yes'}) do
    local _, err = operator.new({fee_payer = bad})
    helper.assert_true(err and err:find('fee_payer', 1, true),
      'expected fee_payer rejection for ' .. tostring(bad))
  end
end)

helper.test('nil-as-no-opinion compose pattern', function()
  demo_signer.reset_for_tests()
  -- Simulates `os.getenv` returning nil for missing env vars.
  local op = assert(operator.new({
    recipient = nil,
    signer    = nil,
    fee_payer = nil,
  }))
  helper.assert_equal(op:signer():demo(), true)
  helper.assert_equal(op:fee_payer(), true)
end)

helper.test('to_summary returns a stable shape', function()
  local sgn = fresh_signer()
  local op = assert(operator.new({recipient = 'RecipientX', signer = sgn}))
  local s = op:to_summary()
  helper.assert_equal(s.recipient, 'RecipientX')
  helper.assert_equal(s.signer_pubkey, sgn:pubkey())
  helper.assert_equal(s.signer_demo, false)
  helper.assert_equal(s.fee_payer, true)
end)
