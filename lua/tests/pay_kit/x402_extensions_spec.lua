--[[
x402 v2 `payment-identifier` extension coverage for the SERVER-only Lua
adapter. Mirrors the rust spine
(rust/crates/x402/src/protocol/schemes/exact/types.rs PaymentExtensions et al.
+ the coinbase payment_identifier.md §5.1.2 echo-and-append / required gate):

  * the PAYMENT-REQUIRED challenge advertises `payment-identifier` with
    info.required=true ONLY when the route is configured to require one, and
    OMITS the `extensions` key entirely otherwise (rust skip_serializing_if =
    Option::is_none — never an empty {}/null);
  * a credential that echoes a valid pay_-shaped id is accepted past the gate;
  * a credential that echoes no id / an empty id / a pattern-violating id is
    rejected with the payment-identifier-required category (HTTP 400 semantics);
  * the id pattern matches rust's ^[A-Za-z0-9_-]{16,128}$ exactly.

The verify-and-settle reject path is exercised before any broadcast, so these
tests are RPC-free (the gate fires ahead of cosign/broadcast).
]]

local helper  = require('tests.test_helper')
local pay_kit = require('pay_kit')
local x402    = require('pay_kit.protocols.x402')
local cjson   = require('cjson.safe')
local base64  = require('pay_kit.util.base64_std')

local SELLER = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'
local MINT   = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'
local PIN_ID = 'pay_abcdef1234567890abcdef1234567890'

local function setup(requires_payment_identifier)
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({
    network  = 'solana_devnet',
    operator = {recipient = SELLER},
    x402     = {requires_payment_identifier = requires_payment_identifier},
  }))
end

local function make_gate()
  assert(pay_kit.gate('paid', {
    amount = assert(pay_kit.usd('0.001', MINT)),
  }))
  return assert(require('pay_kit.internal.registry').materialize('paid'))
end

-- Build a v2 credential whose `accepted` matches the server offer for /paid,
-- with the supplied (or absent) echoed payment-identifier extensions.
local function credential(config, gate, extensions)
  local offer = x402._private.exact_requirement(config, gate, '/paid',
    gate:amount():primary_coin())
  local cred = {
    x402Version = 2,
    accepted    = offer,
    payload     = {transaction = base64.encode('placeholder')},
  }
  if extensions then cred.extensions = extensions end
  return {['payment-signature'] = base64.encode(cjson.encode(cred))}
end

-- --- id pattern (rust ^[A-Za-z0-9_-]{16,128}$) ---------------------

helper.test('ext: payment_identifier_id_valid matches the rust pattern bounds', function()
  local valid = x402._private.payment_identifier_id_valid
  helper.assert_equal(valid(PIN_ID), true)
  helper.assert_equal(valid('pay_7d5d747be160e280504c099d984bcfe0'), true)
  helper.assert_equal(valid(string.rep('a', 16)), true)
  helper.assert_equal(valid(string.rep('a', 128)), true)
  -- too short / too long / bad chars / non-string.
  helper.assert_equal(valid(string.rep('a', 15)), false)
  helper.assert_equal(valid(string.rep('a', 129)), false)
  helper.assert_equal(valid('has spaces in it!!'), false)
  helper.assert_equal(valid(''), false)
  helper.assert_equal(valid(nil), false)
end)

-- --- challenge advertisement ---------------------------------------

helper.test('ext: challenge omits extensions when route does not require one', function()
  setup(false)
  local ch = x402._private.exact_challenge(pay_kit.config(), make_gate(), '/paid')
  helper.assert_equal(ch.extensions, nil)
end)

helper.test('ext: challenge advertises payment-identifier required when configured', function()
  setup(true)
  local ch = x402._private.exact_challenge(pay_kit.config(), make_gate(), '/paid')
  helper.assert_true(type(ch.extensions) == 'table', 'expected extensions table')
  local pid = ch.extensions[x402._private.PAYMENT_IDENTIFIER_KEY]
  helper.assert_true(type(pid) == 'table', 'expected payment-identifier entry')
  helper.assert_equal(pid.info.required, true)
end)

helper.test('ext: advertised challenge round-trips through base64(JSON) verbatim', function()
  setup(true)
  local ch = x402._private.exact_challenge(pay_kit.config(), make_gate(), '/paid')
  local parsed = cjson.decode(base64.decode(
    x402._private.encode_payment_required(ch)))
  helper.assert_equal(parsed.extensions['payment-identifier'].info.required, true)
end)

-- --- helpers (rust requires_payment_identifier / info.id read) -----

helper.test('ext: extensions_requires_payment_identifier reads info.required', function()
  local fn = x402._private.extensions_requires_payment_identifier
  helper.assert_equal(fn({['payment-identifier'] = {info = {required = true}}}), true)
  helper.assert_equal(fn({['payment-identifier'] = {info = {required = false}}}), false)
  helper.assert_equal(fn({['payment-identifier'] = {info = {}}}), false)
  helper.assert_equal(fn({}), false)
  helper.assert_equal(fn(nil), false)
end)

helper.test('ext: extensions_payment_identifier_id reads echoed info.id', function()
  local fn = x402._private.extensions_payment_identifier_id
  helper.assert_equal(fn({['payment-identifier'] = {info = {id = PIN_ID}}}), PIN_ID)
  helper.assert_equal(fn({['payment-identifier'] = {info = {}}}), nil)
  helper.assert_equal(fn(nil), nil)
end)

-- --- server reject gate (verify_and_settle) -------------------------

helper.test('ext: verify_and_settle rejects when required id is missing', function()
  setup(true)
  local config = pay_kit.config()
  local gate = make_gate()
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  -- Echo the extension WITHOUT an id (the server advertised info.required).
  local headers = credential(config, gate,
    {['payment-identifier'] = {info = {required = true}}})
  local _, err = adapter:verify_and_settle(gate, {headers = headers, path = '/paid'})
  helper.assert_true(err and err:find('payment-identifier required', 1, true), tostring(err))
end)

helper.test('ext: verify_and_settle rejects a pattern-violating id', function()
  setup(true)
  local config = pay_kit.config()
  local gate = make_gate()
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  local headers = credential(config, gate,
    {['payment-identifier'] = {info = {required = true, id = 'too short'}}})
  local _, err = adapter:verify_and_settle(gate, {headers = headers, path = '/paid'})
  helper.assert_true(err and err:find('does not match', 1, true), tostring(err))
end)

helper.test('ext: verify_and_settle passes the gate for a valid echoed id', function()
  setup(true)
  local config = pay_kit.config()
  local gate = make_gate()
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  local headers = credential(config, gate,
    {['payment-identifier'] = {info = {required = true, id = PIN_ID}}})
  local _, err = adapter:verify_and_settle(gate, {headers = headers, path = '/paid'})
  -- The credential clears the payment-identifier gate; settlement still fails
  -- downstream because the placeholder transaction is not a real transfer.
  -- The gate-specific message must NOT appear (it would on a missing id).
  helper.assert_true(
    not (err and err:find('payment-identifier required', 1, true)),
    'payment-identifier gate must not fire for a valid id: ' .. tostring(err))
end)

-- --- gate is inert when the route does not require an id ------------

helper.test('ext: no gate when route does not require a payment-identifier', function()
  setup(false)
  local config = pay_kit.config()
  local gate = make_gate()
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  -- No extensions echoed at all; the gate must not fire.
  local headers = credential(config, gate, nil)
  local _, err = adapter:verify_and_settle(gate, {headers = headers, path = '/paid'})
  helper.assert_true(
    not (err and err:find('payment-identifier required', 1, true)),
    'gate must be inert when not required: ' .. tostring(err))
end)
