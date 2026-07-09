--[[
Kong plugin runtime coverage. The existing kong_plugin_spec covers
the static shape (PRIORITY constants, schema fields), but bootstrap
and handler phase methods sit at 0% without a posix-aware test
environment. This spec monkey-patches os.getenv to drive setup()
end-to-end, then drives access() / header_filter() / log() with the
stub `kong` global.

No Kong runtime needed: handler.lua only uses kong.{log, response,
request, ctx} which the spec stubs to capture interactions.
]]

local helper = require('tests.test_helper')

local saved_getenv = os.getenv
local function patch_env(table_values)
  os.getenv = function(name)  -- luacheck: ignore
    if table_values[name] ~= nil then return table_values[name] end
    return saved_getenv(name)
  end
end
local function restore_env()
  os.getenv = saved_getenv  -- luacheck: ignore
end

local exit_calls = {}
local set_headers = {}
local kong_stub = {
  log = {
    err  = function(...) end,
    info = function(...) end,
    warn = function(...) end,
  },
  response = {
    exit = function(status, body, headers)
      exit_calls[#exit_calls + 1] = {status = status, body = body, headers = headers}
    end,
    set_header     = function(k, v) set_headers[k] = v end,
    get_header     = function(_) return nil end,
  },
  request = {
    get_headers = function() return {} end,
    get_path    = function() return '/paid' end,
    get_query   = function() return {} end,
  },
  ctx = {shared = {}},
}
_G.kong = kong_stub

helper.test('Kong bootstrap configures pay_kit from env without posix', function()
  package.loaded['plugins.kong.plugins.pay-kit.init'] = nil
  local pay_kit = require('pay_kit')
  pay_kit._reset_for_tests()
  patch_env({
    PAY_KIT_NETWORK              = 'solana_devnet',
    PAY_KIT_OPERATOR_RECIPIENT   = 'KongMockRecipient0000000000000000000000000',
    PAY_KIT_MPP_CHALLENGE_BINDING_SECRET = 'kong-bootstrap-secret',
    PAY_KIT_ACCEPT               = 'x402,mpp',
    PAY_KIT_STABLECOINS          = 'USDC,USDT',
    PAY_KIT_MPP_REALM            = 'TestKongRealm',
    PAY_KIT_MPP_EXPIRES_IN       = '120',
  })
  local bootstrap = require('plugins.kong.plugins.pay-kit.init')
  bootstrap.setup()
  restore_env()
  local cfg = pay_kit.config()
  helper.assert_equal(cfg.network, 'solana_devnet')
  helper.assert_equal(cfg.mpp.realm, 'TestKongRealm')
  helper.assert_equal(cfg.mpp.expires_in, 120)
end)

helper.test('Kong bootstrap honours empty / blank env defaults', function()
  package.loaded['plugins.kong.plugins.pay-kit.init'] = nil
  local pay_kit = require('pay_kit')
  pay_kit._reset_for_tests()
  patch_env({
    -- PAY_KIT_NETWORK unset -> falls to 'solana_devnet'.
    PAY_KIT_OPERATOR_RECIPIENT   = 'KongDefaultRecipient000000000000000000000',
    PAY_KIT_MPP_CHALLENGE_BINDING_SECRET = 'k',
    PAY_KIT_ACCEPT               = '',
    PAY_KIT_STABLECOINS          = '   ,  ',   -- blank entries -> trimmed
    PAY_KIT_MPP_EXPIRES_IN       = 'not-a-number',
  })
  require('plugins.kong.plugins.pay-kit.init').setup()
  restore_env()
  local cfg = pay_kit.config()
  helper.assert_equal(cfg.network, 'solana_devnet')
  helper.assert_equal(cfg.mpp.expires_in, 300)         -- env_int default
  helper.assert_true(#cfg.accept >= 1)
end)

helper.test('Kong bootstrap surfaces configure() error via error()', function()
  package.loaded['plugins.kong.plugins.pay-kit.init'] = nil
  require('pay_kit')._reset_for_tests()
  patch_env({
    -- Invalid network slug -> configure() rejects.
    PAY_KIT_NETWORK = 'not-a-real-network',
    PAY_KIT_OPERATOR_RECIPIENT = 'Recipient00000000000000000000000000000000',
    PAY_KIT_MPP_CHALLENGE_BINDING_SECRET = 'k',
  })
  local boot = require('plugins.kong.plugins.pay-kit.init')
  local ok, err = pcall(boot.setup)
  restore_env()
  helper.assert_true(not ok, 'expected setup to raise on invalid network')
  helper.assert_true(err ~= nil)
end)

helper.test('Kong handler access(conf) emits 402 on unpaid', function()
  package.loaded['plugins.kong.plugins.pay-kit.handler'] = nil
  require('pay_kit')._reset_for_tests()
  patch_env({
    PAY_KIT_NETWORK = 'solana_devnet',
    PAY_KIT_OPERATOR_RECIPIENT = 'KongAccessRecipient0000000000000000000000',
    PAY_KIT_MPP_CHALLENGE_BINDING_SECRET = 'access-test-key-long-enough-32bytes',
  })
  require('plugins.kong.plugins.pay-kit.init').setup()
  restore_env()

  exit_calls = {}
  local handler = require('plugins.kong.plugins.pay-kit.handler')
  handler:access({amount = '0.001', stablecoins = {'USDC'}})
  helper.assert_equal(#exit_calls, 1)
  helper.assert_equal(exit_calls[1].status, 402)
end)

helper.test('Kong handler access rejects invalid plugin config with 500', function()
  package.loaded['plugins.kong.plugins.pay-kit.handler'] = nil
  require('pay_kit')._reset_for_tests()
  patch_env({
    PAY_KIT_NETWORK = 'solana_devnet',
    PAY_KIT_OPERATOR_RECIPIENT = 'KongAccessRecipient0000000000000000000000',
    PAY_KIT_MPP_CHALLENGE_BINDING_SECRET = 's',
  })
  require('plugins.kong.plugins.pay-kit.init').setup()
  restore_env()

  exit_calls = {}
  local handler = require('plugins.kong.plugins.pay-kit.handler')
  -- amount=garbage -> pay_kit.usd fails -> 500.
  handler:access({amount = 'not-a-decimal', stablecoins = {'USDC'}})
  helper.assert_equal(#exit_calls, 1)
  helper.assert_equal(exit_calls[1].status, 500)
end)

helper.test('Kong handler header_filter stamps settlement headers', function()
  local handler = require('plugins.kong.plugins.pay-kit.handler')
  set_headers = {}
  kong_stub.ctx.shared.pay_kit_payment = {
    settlement_headers = {['x-payment-settlement-signature'] = 'abc123'},
  }
  handler:header_filter({})
  helper.assert_equal(set_headers['x-payment-settlement-signature'], 'abc123')
  kong_stub.ctx.shared.pay_kit_payment = nil
end)

helper.test('Kong handler header_filter / log no-ops when no payment in ctx', function()
  local handler = require('plugins.kong.plugins.pay-kit.handler')
  kong_stub.ctx.shared.pay_kit_payment = nil
  handler:header_filter({})
  handler:log({})
  handler:init_worker()
  helper.assert_true(true)
end)

helper.test('Kong plugin schema loads with stubbed typedefs', function()
  -- Stub kong.db.schema.typedefs so the schema file loads under plain
  -- LuaJIT and we cover its module body.
  package.loaded['kong.db.schema.typedefs'] = package.loaded['kong.db.schema.typedefs'] or {
    protocols_http = {type = 'set', elements = {type = 'string'}},
    no_consumer    = {type = 'boolean', eq = true},
  }
  package.loaded['plugins.kong.plugins.pay-kit.schema'] = nil
  local schema = require('plugins.kong.plugins.pay-kit.schema')
  helper.assert_equal(schema.name, 'pay-kit')
  helper.assert_true(type(schema.fields) == 'table')
  helper.assert_true(#schema.fields >= 3)
end)
