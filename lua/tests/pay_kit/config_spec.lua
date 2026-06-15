--[[
P2 configure() - defaults, mainnet+demo refusal, public-RPC warn,
once-per-worker enforcement, deprecation shims, accessor methods.
]]

local helper = require('tests.test_helper')
local pay_kit = require('pay_kit')
local signer_mod = require('pay_kit.signer')
local errors = require('pay_kit.errors')

local function fresh_signer()
  local bytes = {}
  for i = 1, 64 do bytes[i] = ((i + 31) % 256) end
  return assert(signer_mod.bytes(bytes))
end

local function reset() pay_kit._reset_for_tests() end

helper.test('configure() with no opts boots on demo signer + localnet', function()
  reset()
  local ok = assert(pay_kit.configure())
  helper.assert_equal(ok, true)
  local cfg = pay_kit.config()
  helper.assert_equal(cfg.network, 'solana_localnet')
  -- localnet defaults to the hosted Surfpool clone, not a bare local
  -- validator the developer may not be running (LUA-3 / Ruby parity).
  helper.assert_equal(cfg.rpc_url, 'https://402.surfnet.dev:8899')
  helper.assert_equal(cfg.operator:signer():demo(), true)
  helper.assert_equal(cfg.operator:fee_payer(), true)
end)

helper.test('configure() defaults accept to {x402, mpp}', function()
  reset()
  assert(pay_kit.configure())
  local cfg = pay_kit.config()
  helper.assert_equal(cfg.accept[1], 'x402')
  helper.assert_equal(cfg.accept[2], 'mpp')
end)

helper.test('configure() resolves rpc_url defaults per network', function()
  reset()
  assert(pay_kit.configure({network = 'solana_devnet'}))
  helper.assert_equal(pay_kit.config().rpc_url, 'https://api.devnet.solana.com')
end)

helper.test('configure() honours explicit rpc_url', function()
  reset()
  assert(pay_kit.configure({rpc_url = 'https://my-private.example.com'}))
  helper.assert_equal(pay_kit.config().rpc_url, 'https://my-private.example.com')
  helper.assert_equal(pay_kit.config().using_public_rpc_default, false)
end)

helper.test('configure() refuses mainnet + demo signer', function()
  reset()
  local ok, err = pay_kit.configure({network = 'solana_mainnet'})
  helper.assert_true(ok == nil)
  helper.assert_equal(err, errors.DEMO_SIGNER_ON_MAINNET)
end)

helper.test('configure() accepts mainnet with a real signer', function()
  reset()
  local sgn = fresh_signer()
  assert(pay_kit.configure({
    network  = 'solana_mainnet',
    operator = {signer = sgn},
    rpc_url  = 'https://private.example.com',
  }))
end)

helper.test('configure() rejects unknown network', function()
  reset()
  local _, err = pay_kit.configure({network = 'bitcoin'})
  helper.assert_true(err and err:find('unknown network', 1, true), err)
end)

helper.test('configure() rejects unknown scheme in accept', function()
  reset()
  local _, err = pay_kit.configure({accept = {'stripe'}})
  helper.assert_true(err and err:find('unknown scheme', 1, true), err)
end)

helper.test('configure() rejects empty accept list', function()
  reset()
  local _, err = pay_kit.configure({accept = {}})
  helper.assert_true(err and err:find('non%-empty'), err)
end)

helper.test('configure() rejects empty stablecoins', function()
  reset()
  local _, err = pay_kit.configure({stablecoins = {}})
  helper.assert_true(err and err:find('non%-empty'), err)
end)

helper.test('configure() x402 delegated mode flag', function()
  reset()
  assert(pay_kit.configure({x402 = {facilitator_url = 'https://facilitator.example.com'}}))
  helper.assert_equal(pay_kit.config().x402.delegated, true)
  helper.assert_equal(pay_kit.config().x402.facilitator_url, 'https://facilitator.example.com')
end)

helper.test('configure() default x402 mode is self-hosted (not delegated)', function()
  reset()
  assert(pay_kit.configure())
  helper.assert_equal(pay_kit.config().x402.delegated, false)
  helper.assert_equal(pay_kit.config().x402.facilitator_url, nil)
end)

helper.test('configure() effective_x402_signer defaults to operator.signer', function()
  reset()
  local sgn = fresh_signer()
  assert(pay_kit.configure({operator = {signer = sgn}}))
  local cfg = pay_kit.config()
  helper.assert_equal(cfg:effective_x402_signer():pubkey(), sgn:pubkey())
end)

helper.test('configure() x402.signer override is honoured', function()
  reset()
  local op_sgn = fresh_signer()
  local x_sgn = fresh_signer()
  assert(pay_kit.configure({
    operator = {signer = op_sgn},
    x402     = {signer = x_sgn},
  }))
  helper.assert_equal(pay_kit.config():effective_x402_signer():pubkey(), x_sgn:pubkey())
end)

helper.test('configure() effective_recipient cascades to signer pubkey', function()
  reset()
  local sgn = fresh_signer()
  assert(pay_kit.configure({operator = {signer = sgn}}))
  helper.assert_equal(pay_kit.config():effective_recipient(), sgn:pubkey())
end)

helper.test('configure() effective_recipient honours explicit operator.recipient', function()
  reset()
  assert(pay_kit.configure({operator = {recipient = 'Recipient333'}}))
  helper.assert_equal(pay_kit.config():effective_recipient(), 'Recipient333')
end)

helper.test('configure() mpp.challenge_binding_secret is stored', function()
  reset()
  assert(pay_kit.configure({mpp = {challenge_binding_secret = 'rotate-me-key-long-enough-32bytes!!'}}))
  helper.assert_equal(pay_kit.config().mpp.challenge_binding_secret, 'rotate-me-key-long-enough-32bytes!!')
end)

helper.test('configure() mpp.expires_in default + override', function()
  reset()
  assert(pay_kit.configure())
  helper.assert_equal(pay_kit.config().mpp.expires_in, 300)

  reset()
  assert(pay_kit.configure({mpp = {expires_in = 60}}))
  helper.assert_equal(pay_kit.config().mpp.expires_in, 60)
end)

-- Regression: configure() must preserve a caller-supplied mpp.replay_store
-- (and any other mpp.* field) through to the stored config. A prior round-1
-- change rebuilt current_config.mpp from only realm / secret / expires_in,
-- silently dropping the shared atomic replay store operators inject to
-- satisfy the multi-worker replay-protection warning. Pre-fix the assert on
-- replay_store fails (nil); post-fix it round-trips.
helper.test('configure() preserves mpp.replay_store and other mpp fields', function()
  reset()
  local sentinel_store = { put_if_absent = function() return true end }
  assert(pay_kit.configure({mpp = {
    replay_store = sentinel_store,
    challenge_binding_secret = 'rotate-me-key-long-enough-32bytes!!',
    expires_in = 90,
  }}))
  local cfg = pay_kit.config()
  helper.assert_equal(cfg.mpp.replay_store, sentinel_store)
  -- Normalized fields still applied alongside the preserved store.
  helper.assert_equal(cfg.mpp.challenge_binding_secret, 'rotate-me-key-long-enough-32bytes!!')
  helper.assert_equal(cfg.mpp.expires_in, 90)
  helper.assert_equal(cfg.mpp.realm, 'App')
end)

helper.test('configure() refuses to be called twice', function()
  reset()
  assert(pay_kit.configure())
  local _, err = pay_kit.configure()
  helper.assert_equal(err, errors.CONFIGURE_ALREADY_CALLED)
end)
