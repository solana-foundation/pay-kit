--[[
P4 Gate + Fee + registry. Static + inline + dynamic forms; rules
1-6 from the design's "Amount and fees" section enforced at
registration time.
]]

local helper   = require('tests.test_helper')
local pay_kit  = require('pay_kit')
local registry = require('pay_kit.internal.registry')
local errors   = require('pay_kit.errors')

local SELLER   = 'SeLLeRWaLLeT111111111111111111111111111111'
local PLATFORM = 'PLaTFoRmWaLLeT11111111111111111111111111111'

local function setup()
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({
    operator = {recipient = 'OperatorRecipient0000000000000000000000000'},
  }))
end

-- --- static registration --------------------------------------------

helper.test('gate() registers a simple static gate', function()
  setup()
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  helper.assert_true(registry.has('report'))
end)

helper.test('gate() inherits pay_to from operator', function()
  setup()
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local g = assert(registry.materialize('report'))
  helper.assert_equal(g:pay_to(), 'OperatorRecipient0000000000000000000000000')
end)

helper.test('gate() honours explicit pay_to', function()
  setup()
  assert(pay_kit.gate('marketplace', {amount = assert(pay_kit.usd('1.00')), pay_to = SELLER}))
  local g = assert(registry.materialize('marketplace'))
  helper.assert_equal(g:pay_to(), SELLER)
end)

helper.test('gate() inherits accept from config', function()
  setup()
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local g = assert(registry.materialize('report'))
  local a = g:accept()
  helper.assert_equal(a[1], 'x402')
  helper.assert_equal(a[2], 'mpp')
end)

-- --- inline ---------------------------------------------------------

helper.test('registry.build_inline builds a one-off Gate', function()
  setup()
  local g = assert(registry.build_inline({
    amount = assert(pay_kit.usd('0.25')),
    description = 'One-off',
  }))
  helper.assert_equal(g:amount():units(), 250000)
  helper.assert_equal(g:description(), 'One-off')
end)

-- --- dynamic --------------------------------------------------------

helper.test('gate() accepts a function for dynamic pricing', function()
  setup()
  assert(pay_kit.gate('tiered', function(req)
    if req and req.query and req.query.tier == 'premium' then
      return {amount = assert(pay_kit.usd('5.00'))}
    end
    return {amount = assert(pay_kit.usd('0.10'))}
  end))

  local basic = assert(registry.materialize('tiered', {query = {}}))
  helper.assert_equal(basic:amount():units(), 100000)

  local premium = assert(registry.materialize('tiered', {query = {tier = 'premium'}}))
  helper.assert_equal(premium:amount():units(), 5000000)
end)

helper.test('dynamic gate that throws surfaces a clean error', function()
  setup()
  assert(pay_kit.gate('boom', function() error('boom') end))
  local _, err = registry.materialize('boom', {})
  helper.assert_true(err and err:find('boom', 1, true), err)
end)

-- --- rules 1-6 ------------------------------------------------------

helper.test('rule 2: pay_to required (operator without recipient, no gate pay_to)', function()
  pay_kit._reset_for_tests()
  -- Configure without explicit recipient and with a non-demo signer
  -- so effective_recipient is the signer pubkey. Then a gate must
  -- still resolve a pay_to via that cascade.
  assert(pay_kit.configure())
  assert(pay_kit.gate('default', {amount = assert(pay_kit.usd('0.10'))}))
  local g = assert(registry.materialize('default'))
  helper.assert_true(type(g:pay_to()) == 'string' and #g:pay_to() > 0)
end)

helper.test('rule 3: mixed denominations rejected', function()
  -- This case is structurally hard to hit in v1 because all factories
  -- under usd() share denomination "USD". When eur/gbp helpers ship,
  -- their denominations differ and this rule fires. For now we test
  -- the validator directly via a synthetic Fee/Price.
  setup()
  local fee_mod = require('pay_kit.internal.fee')
  -- Hand-build a Price-like with a different denomination.
  local fake_eur = setmetatable({}, {__index = {
    units        = function() return 10 end,
    denomination = function() return 'EUR' end,
    amount_string = function() return '0.000010' end,
    settlements  = function() return {'USDC'} end,
    primary_coin = function() return 'USDC' end,
  }})
  local fake_fee = assert(fee_mod.new(PLATFORM, fake_eur, 'within'))
  local gate_mod = require('pay_kit.internal.gate')
  local _, err = gate_mod.build({
    name = 'mixed',
    amount = assert(pay_kit.usd('1.00')),
    pay_to = SELLER,
    -- pass via the array form to bypass hash sort that would shuffle
    fee_within = {{PLATFORM, fake_eur}},
  }, {pay_to = SELLER, accept = {'mpp'}})
  helper.assert_true(err and err:find('denomination', 1, true), err)
  -- silence unused-local lints
  if not fake_fee then return end
end)

helper.test('rule 4: sum(fee_within) <= amount enforced', function()
  setup()
  local _, err = pay_kit.gate('over_within', {
    amount = assert(pay_kit.usd('1.00')),
    pay_to = SELLER,
    fee_within = {[PLATFORM] = assert(pay_kit.usd('2.00'))},
  })
  helper.assert_true(err and err:find('exceeds amount', 1, true), err)
end)

helper.test('rule 5: x402 auto-disabled when fees present', function()
  setup()
  assert(pay_kit.gate('marketplace', {
    amount = assert(pay_kit.usd('1.00')),
    pay_to = SELLER,
    fee_within = {[PLATFORM] = assert(pay_kit.usd('0.10'))},
  }))
  local g = assert(registry.materialize('marketplace'))
  helper.assert_equal(g:x402_accepted(), false)
  helper.assert_equal(g:mpp_accepted(), true)
end)

helper.test('rule 5: explicit accept x402 + fees raises', function()
  setup()
  local _, err = pay_kit.gate('marketplace', {
    amount = assert(pay_kit.usd('1.00')),
    pay_to = SELLER,
    fee_within = {[PLATFORM] = assert(pay_kit.usd('0.10'))},
    accept = {'x402'},
  })
  helper.assert_equal(err, errors.X402_INCOMPATIBLE_WITH_FEES)
end)

helper.test('fee recipient duplicating pay_to is rejected', function()
  setup()
  local _, err = pay_kit.gate('dup', {
    amount = assert(pay_kit.usd('1.00')),
    pay_to = SELLER,
    fee_within = {[SELLER] = assert(pay_kit.usd('0.10'))},
  })
  helper.assert_true(err and err:find('duplicates pay_to', 1, true), err)
end)

-- --- total / fee shape ----------------------------------------------

helper.test('gate.total_units = amount + sum(fee_on_top)', function()
  setup()
  assert(pay_kit.gate('ticket', {
    amount = assert(pay_kit.usd('10.00')),
    pay_to = SELLER,
    fee_on_top = {[PLATFORM] = assert(pay_kit.usd('0.50'))},
  }))
  local g = assert(registry.materialize('ticket'))
  helper.assert_equal(g:total_units(), 10500000)
end)

helper.test('gate.fees returns within first, then on_top', function()
  setup()
  assert(pay_kit.gate('split', {
    amount = assert(pay_kit.usd('10.00')),
    pay_to = SELLER,
    fee_within = {[PLATFORM] = assert(pay_kit.usd('0.30'))},
    fee_on_top = {[PLATFORM .. '2'] = assert(pay_kit.usd('0.20'))},
  }))
  local g = assert(registry.materialize('split'))
  local fees = g:fees()
  helper.assert_equal(#fees, 2)
  helper.assert_equal(fees[1]:within(), true)
  helper.assert_equal(fees[2]:on_top(), true)
end)

-- --- duplicate / lookup ---------------------------------------------

helper.test('duplicate registration rejected', function()
  setup()
  assert(pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))}))
  local _, err = pay_kit.gate('report', {amount = assert(pay_kit.usd('0.10'))})
  helper.assert_true(err and err:find('duplicate gate', 1, true), err)
end)

helper.test('materialize for unknown gate returns error', function()
  setup()
  local _, err = registry.materialize('nope')
  helper.assert_equal(err, errors.GATE_NOT_FOUND)
end)

-- --- freeze ---------------------------------------------------------

helper.test('registry.freeze blocks subsequent registrations', function()
  setup()
  registry.freeze()
  local _, err = pay_kit.gate('late', {amount = assert(pay_kit.usd('0.10'))})
  helper.assert_equal(err, errors.GATE_REGISTRATION_FROZEN)
end)
