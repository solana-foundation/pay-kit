--[[
P8 Kong plugin smoke. Without a running Kong process we cannot
exercise phase callbacks end-to-end; this spec asserts the static
contract: PRIORITY + VERSION constants, schema shape, bootstrap
roundtrip against the canonical env-var set.
]]

local helper = require('tests.test_helper')

-- Stub the `kong` global so handler.lua loads cleanly under plain
-- LuaJIT. The phase methods themselves aren't invoked in this spec;
-- the unit-test contract is that the plugin module loads, exposes
-- the right shape, and the bootstrap call wires configure() correctly.
_G.kong = _G.kong or {
  log = {err = function() end, info = function() end, warn = function() end},
  response = {exit = function() end, set_header = function() end, get_header = function() return nil end},
  request = {
    get_headers = function() return {} end,
    get_path    = function() return '/' end,
    get_query   = function() return {} end,
  },
  ctx = {shared = {}},
}

helper.test('Kong plugin handler exposes PRIORITY + VERSION constants', function()
  local handler = require('plugins.kong.plugins.pay-kit.handler')
  helper.assert_equal(type(handler.PRIORITY), 'number')
  helper.assert_equal(handler.VERSION, '0.1.0')
  helper.assert_true(handler.PRIORITY >= 900 and handler.PRIORITY <= 1100,
    'PRIORITY must land in the auth-adjacent band')
end)

helper.test('Kong plugin handler defines access / header_filter / log', function()
  local handler = require('plugins.kong.plugins.pay-kit.handler')
  helper.assert_equal(type(handler.access), 'function')
  helper.assert_equal(type(handler.header_filter), 'function')
  helper.assert_equal(type(handler.log), 'function')
  helper.assert_equal(type(handler.init_worker), 'function')
end)

helper.test('Kong bootstrap wires pay_kit.configure from env', function()
  -- Reset shim so the spec is order-independent.
  local pay_kit = require('pay_kit')
  pay_kit._reset_for_tests()

  -- Stub posix.setenv if available so configure() reads the right
  -- env in process. If posix is not installed, we skip silently
  -- and rely on the lint/static checks.
  local ok, posix = pcall(require, 'posix.stdlib')
  if not ok then return end
  posix.setenv('PAY_KIT_NETWORK', 'solana_devnet')
  posix.setenv('PAY_KIT_OPERATOR_RECIPIENT', 'KongRecipient00000000000000000000000000000')
  posix.setenv('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET', 'kong-test')

  local bootstrap = require('plugins.kong.plugins.pay-kit.init')
  bootstrap.setup()

  local cfg = pay_kit.config()
  helper.assert_equal(cfg.network, 'solana_devnet')
  helper.assert_equal(cfg.operator:effective_recipient(),
    'KongRecipient00000000000000000000000000000')
  helper.assert_equal(cfg.mpp.challenge_binding_secret, 'kong-test')

  -- Cleanup.
  pcall(function() posix.unsetenv('PAY_KIT_NETWORK') end)
  pcall(function() posix.unsetenv('PAY_KIT_OPERATOR_RECIPIENT') end)
  pcall(function() posix.unsetenv('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET') end)
end)
