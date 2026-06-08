--[[
P5 x402 adapter wire-format coverage. The full broadcast / verifier
port is exercised by the cross-language harness in P11; these tests
pin the matching + envelope shape so a regression on the wire is
caught at the gem level.
]]

local helper   = require('tests.test_helper')
local pay_kit  = require('pay_kit')
local x402     = require('pay_kit.protocols.x402')
local cjson    = require('cjson.safe')

local SELLER = 'SeLLeRWaLLeT111111111111111111111111111111'

local function setup()
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({
    network  = 'solana_devnet',
    operator = {recipient = SELLER},
  }))
end

local function make_gate(price_str)
  assert(pay_kit.gate('paid', {
    amount = assert(pay_kit.usd(price_str or '0.001',
      '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU')),
  }))
  return assert(require('pay_kit.internal.registry').materialize('paid'))
end

-- --- detect ---------------------------------------------------------

helper.test('detect: returns true for non-empty PAYMENT-SIGNATURE header', function()
  helper.assert_equal(x402.detect({['payment-signature'] = 'abc'}), true)
  helper.assert_equal(x402.detect({['PAYMENT-SIGNATURE'] = 'abc'}), true)
end)

helper.test('detect: returns false for empty or missing header', function()
  helper.assert_equal(x402.detect({}), false)
  helper.assert_equal(x402.detect({['payment-signature'] = ''}), false)
  helper.assert_equal(x402.detect(nil), false)
end)

-- --- matcher --------------------------------------------------------

helper.test('matcher: identity tuple match ignores amount/maxTimeoutSeconds', function()
  local client = {
    scheme  = 'exact',
    network = 'solana:dev',
    asset   = 'MintAddr',
    payTo   = SELLER,
    extra   = {feePayer = 'Fp', tokenProgram = 'Tk', memo = '/paid'},
  }
  local server = {
    scheme            = 'exact',
    network           = 'solana:dev',
    asset             = 'MintAddr',
    amount            = '100',
    maxAmountRequired = '100',
    payTo             = SELLER,
    maxTimeoutSeconds = 60,
    extra             = {feePayer = 'Fp', tokenProgram = 'Tk', memo = '/paid', decimals = 6},
  }
  helper.assert_equal(x402._private.accepted_requirement_matches(client, server), true)
end)

helper.test('matcher: scheme/network/asset/payTo mismatch returns false', function()
  local server = {scheme = 'exact', network = 'solana:dev', asset = 'A', payTo = 'P'}
  helper.assert_equal(x402._private.accepted_requirement_matches(
    {scheme = 'other', network = 'solana:dev', asset = 'A', payTo = 'P'}, server), false)
  helper.assert_equal(x402._private.accepted_requirement_matches(
    {scheme = 'exact', network = 'solana:other', asset = 'A', payTo = 'P'}, server), false)
  helper.assert_equal(x402._private.accepted_requirement_matches(
    {scheme = 'exact', network = 'solana:dev', asset = 'B', payTo = 'P'}, server), false)
  helper.assert_equal(x402._private.accepted_requirement_matches(
    {scheme = 'exact', network = 'solana:dev', asset = 'A', payTo = 'Q'}, server), false)
end)

helper.test('matcher: tolerates unknown extra keys on the client side', function()
  local server = {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p', extra = {feePayer = 'f'}}
  local client = {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p',
                  extra = {feePayer = 'f', unexpected = 'drift'}}
  helper.assert_equal(x402._private.accepted_requirement_matches(client, server), true)
end)

helper.test('matcher: server-side canonical extra mismatch returns false', function()
  local server = {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p',
                  extra = {feePayer = 'server_fp'}}
  local client = {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p',
                  extra = {feePayer = 'attacker_fp'}}
  helper.assert_equal(x402._private.accepted_requirement_matches(client, server), false)
end)

-- --- challenge envelope --------------------------------------------

helper.test('exact_challenge envelope shape', function()
  setup()
  local gate = make_gate('0.001')
  local config = pay_kit.config()
  local ch = x402._private.exact_challenge(config, gate, '/paid')
  helper.assert_equal(ch.x402Version, 2)
  helper.assert_equal(ch.resource.type, 'http')
  helper.assert_equal(ch.resource.url, '/paid')
  helper.assert_equal(ch.resource.uri, '/paid')
  helper.assert_equal(#ch.accepts, 1)
  local req = ch.accepts[1]
  helper.assert_equal(req.scheme, 'exact')
  helper.assert_equal(req.network, x402._private.caip2_for('solana_devnet'))
  helper.assert_equal(req.payTo, SELLER)
  helper.assert_equal(req.amount, '1000')                -- 0.001 USDC = 1000 micro
  helper.assert_equal(req.maxAmountRequired, '1000')
  helper.assert_equal(req.maxTimeoutSeconds, 60)
  helper.assert_equal(req.extra.memo, '/paid')
  helper.assert_equal(req.extra.tokenProgram, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
end)

helper.test('encode_payment_required is base64 of JSON', function()
  setup()
  local gate = make_gate('0.001')
  local ch = x402._private.exact_challenge(pay_kit.config(), gate, '/paid')
  local encoded = x402._private.encode_payment_required(ch)
  -- Decode and verify roundtrip.
  local base64 = require('pay_kit.util.base64_std')
  local decoded = base64.decode(encoded)
  helper.assert_true(decoded ~= nil)
  local parsed = cjson.decode(decoded)
  helper.assert_equal(parsed.x402Version, 2)
  helper.assert_equal(parsed.accepts[1].payTo, SELLER)
end)

-- --- credential decoding --------------------------------------------

helper.test('decode_payment_signature rejects empty header', function()
  local _, err = x402._private.decode_payment_signature('')
  helper.assert_true(err and err:find('payment required', 1, true), err)
end)

helper.test('decode_payment_signature rejects unsupported version', function()
  local base64 = require('pay_kit.util.base64_std')
  local encoded = base64.encode(cjson.encode({x402Version = 1}))
  local _, err = x402._private.decode_payment_signature(encoded)
  helper.assert_true(err and err:find('unsupported x402Version', 1, true), err)
end)

helper.test('decode_payment_signature accepts v2 envelope', function()
  local base64 = require('pay_kit.util.base64_std')
  local body = {x402Version = 2, accepted = {}, payload = {}}
  local encoded = base64.encode(cjson.encode(body))
  local env = assert(x402._private.decode_payment_signature(encoded))
  helper.assert_equal(env.x402Version, 2)
end)

-- --- mismatch flow --------------------------------------------------

helper.test('verify_and_settle rejects unmatched accepted', function()
  setup()
  local gate = make_gate('0.001')
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  local base64 = require('pay_kit.util.base64_std')
  local cred = {
    x402Version = 2,
    accepted    = {scheme = 'exact', network = 'solana:wrong', asset = 'wrong', payTo = 'wrong'},
    payload     = {transaction = base64.encode('placeholder')},
  }
  local headers = {['payment-signature'] = base64.encode(cjson.encode(cred))}
  local _, err = adapter:verify_and_settle(gate, {headers = headers, path = '/paid'})
  helper.assert_true(err and err:find('does not match', 1, true), err)
end)

-- --- legacy v1 dual-accept ------------------------------------------
--
-- The legacy v1 X-PAYMENT wire carries x402Version=1 with scheme + network
-- as top-level siblings of payload and no accepted object. The server reads
-- the v2 PAYMENT-SIGNATURE wire first, then falls back to v1; it binds only
-- scheme + network for v1, normalizes the plain SVM slug, and still rejects
-- a genuinely-unknown version. Mirrors rust parse_payment_signature
-- (server/exact.rs:316-346).

local function encode_legacy(body)
  local base64 = require('pay_kit.util.base64_std')
  return base64.encode(cjson.encode(body))
end

helper.test('detect: returns true for non-empty X-PAYMENT (legacy v1) header', function()
  helper.assert_equal(x402.detect({['x-payment'] = 'abc'}), true)
  helper.assert_equal(x402.detect({['X-PAYMENT'] = 'abc'}), true)
end)

helper.test('detect: false when only an empty X-PAYMENT header is present', function()
  helper.assert_equal(x402.detect({['x-payment'] = ''}), false)
end)

helper.test('legacy_network_slug maps pay-kit network to plain SVM slug', function()
  helper.assert_equal(x402._private.legacy_network_slug('solana_mainnet'), 'solana')
  helper.assert_equal(x402._private.legacy_network_slug('solana_devnet'), 'solana-devnet')
  helper.assert_equal(x402._private.legacy_network_slug('solana_localnet'), 'solana-devnet')
  helper.assert_equal(x402._private.legacy_network_slug('solana_testnet'), 'solana-testnet')
end)

helper.test('caip2_network_for_cluster normalizes plain slugs to CAIP-2', function()
  local p = x402._private
  helper.assert_equal(p.caip2_network_for_cluster('solana'), p.caip2_for('solana_mainnet'))
  helper.assert_equal(p.caip2_network_for_cluster('mainnet-beta'), p.caip2_for('solana_mainnet'))
  helper.assert_equal(p.caip2_network_for_cluster('solana-devnet'), p.caip2_for('solana_devnet'))
  helper.assert_equal(p.caip2_network_for_cluster('devnet'), p.caip2_for('solana_devnet'))
  helper.assert_equal(p.caip2_network_for_cluster('localnet'), p.caip2_for('solana_devnet'))
end)

helper.test('decode_legacy_payment accepts a v1 envelope', function()
  local env = assert(x402._private.decode_legacy_payment(encode_legacy({
    x402Version = 1,
    scheme      = 'exact',
    network     = 'solana-devnet',
    payload     = {transaction = 'AA=='},
  })))
  helper.assert_equal(env.x402Version, 1)
  helper.assert_equal(env.scheme, 'exact')
  helper.assert_equal(env.network, 'solana-devnet')
end)

helper.test('decode_legacy_payment rejects a non-v1 version', function()
  local _, err = x402._private.decode_legacy_payment(encode_legacy({
    x402Version = 2, scheme = 'exact', network = 'solana',
  }))
  helper.assert_true(err and err:find('unsupported x402Version', 1, true), err)
end)

helper.test('decode_legacy_payment rejects a non-exact scheme', function()
  local _, err = x402._private.decode_legacy_payment(encode_legacy({
    x402Version = 1, scheme = 'upto', network = 'solana',
  }))
  helper.assert_true(err and err:find('scheme is not exact', 1, true), err)
end)

helper.test('decode_legacy_payment rejects an empty header', function()
  local _, err = x402._private.decode_legacy_payment('')
  helper.assert_true(err and err:find('payment required', 1, true), err)
end)

helper.test('resolve_credential reads the v2 PAYMENT-SIGNATURE wire first', function()
  local v2 = encode_legacy({x402Version = 2, accepted = {}, payload = {}})
  local v1 = encode_legacy({x402Version = 1, scheme = 'exact', network = 'solana'})
  local env, is_legacy = assert(x402._private.resolve_credential({
    ['payment-signature'] = v2,
    ['x-payment']         = v1,
  }))
  helper.assert_equal(env.x402Version, 2)
  helper.assert_equal(is_legacy, false)
end)

helper.test('resolve_credential falls back to the v1 X-PAYMENT wire', function()
  local v1 = encode_legacy({x402Version = 1, scheme = 'exact', network = 'solana-devnet',
    payload = {transaction = 'AA=='}})
  local env, is_legacy = assert(x402._private.resolve_credential({['x-payment'] = v1}))
  helper.assert_equal(env.x402Version, 1)
  helper.assert_equal(is_legacy, true)
end)

helper.test('resolve_credential rejects a genuinely-unknown version on the v1 wire', function()
  local unknown = encode_legacy({x402Version = 9, scheme = 'exact', network = 'solana'})
  local env, _, _, err = x402._private.resolve_credential({['x-payment'] = unknown})
  helper.assert_true(env == nil)
  helper.assert_true(err and err:find('unsupported x402Version', 1, true), err)
end)

helper.test('resolve_credential returns payment-required when no credential header is present', function()
  local env, _, _, err = x402._private.resolve_credential({})
  helper.assert_true(env == nil)
  helper.assert_true(err and err:find('payment required', 1, true), err)
end)

helper.test('verify_and_settle rejects a v1 credential signed for the wrong network', function()
  setup()  -- server configured for solana_devnet
  local gate = make_gate('0.001')
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  local base64 = require('pay_kit.util.base64_std')
  -- v1 envelope with plain "solana" (mainnet) presented to a devnet route.
  local v1 = base64.encode(cjson.encode({
    x402Version = 1,
    scheme      = 'exact',
    network     = 'solana',
    payload     = {transaction = base64.encode('placeholder')},
  }))
  local _, err = adapter:verify_and_settle(gate, {headers = {['x-payment'] = v1}, path = '/paid'})
  helper.assert_true(err and err:find('wrong network', 1, true), err)
end)

helper.test('verify_and_settle passes a matching-network v1 credential past the network gate', function()
  setup()  -- server configured for solana_devnet
  local gate = make_gate('0.001')
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  local base64 = require('pay_kit.util.base64_std')
  -- v1 envelope with plain "solana-devnet" against a devnet route: the
  -- network gate passes, so the failure must come from the missing payload
  -- transaction proof, NOT a network/version mismatch. This pins that the
  -- v1 arm binds scheme + network and then proceeds to the shared MUST-check
  -- path identical to v2.
  local v1 = base64.encode(cjson.encode({
    x402Version = 1,
    scheme      = 'exact',
    network     = 'solana-devnet',
    payload     = {},  -- no transaction: must fail AFTER the network gate
  }))
  local _, err = adapter:verify_and_settle(gate, {headers = {['x-payment'] = v1}, path = '/paid'})
  helper.assert_true(err and err:find('payload missing transaction', 1, true), err)
  helper.assert_true(not err:find('wrong network', 1, true), 'must pass the network gate')
end)
