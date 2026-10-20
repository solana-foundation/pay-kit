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

helper.test('matcher: identity tuple match ignores maxTimeoutSeconds', function()
  local client = {
    scheme  = 'exact',
    network = 'solana:dev',
    asset   = 'MintAddr',
    amount  = '100',
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

-- x402-specification-v2.md §5.2.2: `accepted` is the chosen requirement,
-- amount included. A credential claiming a cheaper amount is a mismatch.
helper.test('matcher: accepted.amount must equal the offered amount', function()
  local server = {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p', amount = '1000'}
  helper.assert_equal(x402._private.accepted_requirement_matches(
    {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p', amount = '1000'}, server), true)
  helper.assert_equal(x402._private.accepted_requirement_matches(
    {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p', amount = '1'}, server), false)
  helper.assert_equal(x402._private.accepted_requirement_matches(
    {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p'}, server), false)
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
  -- RULINGS X1: `maxAmountRequired` is the v1 field, not a v2 one.
  helper.assert_equal(req.maxAmountRequired, nil)
  helper.assert_equal(req.maxTimeoutSeconds, 60)
  helper.assert_equal(req.extra.memo, '/paid')
  helper.assert_equal(req.extra.tokenProgram, 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
end)

-- A configured ticker reaches the wire as its mint, and a Token-2022
-- stablecoin is not advertised under the legacy token program.
helper.test('exact_requirement resolves the settlement coin to its mint', function()
  setup()
  assert(pay_kit.gate('paid', {amount = assert(pay_kit.usd('0.001', 'USDC'))}))
  local usdc = assert(require('pay_kit.internal.registry').materialize('paid'))
  local req = x402._private.exact_requirement(pay_kit.config(), usdc, '/paid', 'USDC')
  helper.assert_equal(req.asset, '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU')

  local pyusd = x402._private.exact_requirement(pay_kit.config(), usdc, '/paid', 'PYUSD')
  helper.assert_equal(pyusd.asset, 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM')
  helper.assert_equal(pyusd.extra.tokenProgram, 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
end)

-- RULINGS X2 / C2: a 9-decimal mint is priced in its own atomic units on
-- both protocols (0.001 -> 1000000), not as if it had 6 decimals.
helper.test('offers price a 9-decimal mint in its own atomic units', function()
  local mint = 'KTHzp63RATgvE5RoRRqVbY7hMWntARQ6dPQhMtfY9oA'
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({
    network = 'solana_devnet', operator = {recipient = SELLER}, preflight = false,
    stablecoins = {mint}, asset_decimals = {[mint] = 9},
    mpp = {challenge_binding_secret = 'x402-spec-secret-0123456789abcdef'},
  }))
  assert(pay_kit.gate('nine', {amount = assert(pay_kit.usd('0.001', mint))}))
  local gate = assert(require('pay_kit.internal.registry').materialize('nine'))

  local req = x402._private.exact_requirement(pay_kit.config(), gate, '/paid', mint)
  helper.assert_equal(req.amount, '1000000')
  helper.assert_equal(req.extra.decimals, 9)

end)

-- The MPP adapter takes decimals from the coin too: 0.001 SOL is 1000000
-- lamports (it used to scale every coin by 10^6, giving 1000).
helper.test('MPP adapter prices SOL in lamports', function()
  pay_kit._reset_for_tests()
  assert(pay_kit.configure({
    network = 'solana_devnet', operator = {recipient = SELLER}, preflight = false,
    accept = {'mpp'}, stablecoins = {'SOL'},
    mpp = {challenge_binding_secret = 'x402-spec-secret-0123456789abcdef'},
  }))
  assert(pay_kit.gate('sol', {amount = assert(pay_kit.usd('0.001', 'SOL'))}))
  local gate = assert(require('pay_kit.internal.registry').materialize('sol'))
  local mpp = require('pay_kit.protocols.mpp')
  local adapter = assert(mpp.new({config_resolver = pay_kit.config}))
  helper.assert_equal(adapter:accepts_entry(gate, {path = '/paid'}).amount, '1000000')
end)

helper.test('exact_requirement binds no memo when there is no resource', function()
  setup()
  local gate = make_gate('0.001')
  local req = x402._private.exact_requirement(pay_kit.config(), gate, nil, gate:amount():primary_coin())
  helper.assert_equal(req.extra.memo, nil)
end)

-- RULINGS S1: extra.tokenProgram / extra.decimals are non-spec hints, so an
-- `accepted` echo that omits them still binds to the offer.
helper.test('matcher: ignores the non-spec tokenProgram and decimals hints', function()
  local server = {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p',
                  extra = {feePayer = 'f', tokenProgram = 't', decimals = 6, memo = '/paid'}}
  local client = {scheme = 'exact', network = 'n', asset = 'a', payTo = 'p',
                  extra = {feePayer = 'f', memo = '/paid'}}
  helper.assert_equal(x402._private.accepted_requirement_matches(client, server), true)
  client.extra.memo = '/other'
  helper.assert_equal(x402._private.accepted_requirement_matches(client, server), false)
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

-- RULINGS S3: pre-broadcast verification inspects the transaction. A
-- credential whose `accepted` matches the route (positive control: it gets
-- past the offer binding) but whose transaction is not a payment is rejected
-- by the structural verifier, never accepted on the envelope alone.
helper.test('verify_payment runs the structural verifier on a route-matching credential', function()
  setup()
  local gate = make_gate('0.001')
  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  local base64 = require('pay_kit.util.base64_std')
  local offer = x402._private.exact_requirement(pay_kit.config(), gate, nil, gate:amount():primary_coin())
  local cred = {x402Version = 2, accepted = offer, payload = {transaction = base64.encode('placeholder')}}
  local headers = {['payment-signature'] = base64.encode(cjson.encode(cred))}
  local result, err = adapter:verify_payment(gate, {headers = headers}, nil)
  helper.assert_equal(result, nil)
  helper.assert_true(err and err:find('invalid_exact_svm_payload', 1, true), err)
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
