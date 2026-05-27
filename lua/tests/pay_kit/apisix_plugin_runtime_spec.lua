--[[
APISIX plugin runtime coverage. Drives _M.access(conf, ctx) and
header_filter end-to-end against a stubbed apisix.core surface,
mirrored on the kong_plugin_runtime spec.
]]

local helper = require('tests.test_helper')

-- Stub apisix.core. The plugin only consumes a handful of helpers.
package.loaded['apisix.core'] = package.loaded['apisix.core'] or {
  log     = {error = function() end, warn = function() end, info = function() end},
  schema  = {check = function() return true end},
  request = {
    headers       = function() return {} end,
    get_uri_args  = function() return {} end,
  },
  response = {set_header = function() end},
}

local set_headers = {}
package.loaded['apisix.core'].response.set_header =
  function(k, v) set_headers[k] = v end

local pay_kit = require('pay_kit')

helper.test('APISIX access(conf,ctx) returns 402 on unpaid', function()
  pay_kit._reset_for_tests()
  pay_kit.configure({
    network = 'solana_devnet',
    rpc_url = 'https://api.devnet.solana.com',
    accept  = {'x402', 'mpp'},
    operator = {recipient = 'ApisixRecipient000000000000000000000000000'},
    mpp = {realm = 'APISIX', challenge_binding_secret = 'apx-secret'},
  })

  local plugin = require('plugins.apisix.plugins.pay-kit')
  local ctx = {var = {uri = '/api/v1'}}
  local status, body = plugin.access(
    {amount = '0.001', stablecoins = {'USDC'}}, ctx)
  helper.assert_equal(status, 402)
  helper.assert_true(type(body) == 'table')
end)

helper.test('APISIX access returns 500 on invalid amount', function()
  pay_kit._reset_for_tests()
  pay_kit.configure({
    network = 'solana_devnet',
    rpc_url = 'https://api.devnet.solana.com',
    accept  = {'x402', 'mpp'},
    operator = {recipient = 'ApisixRecipient000000000000000000000000000'},
    mpp = {realm = 'APISIX', challenge_binding_secret = 'apx-secret'},
  })
  local plugin = require('plugins.apisix.plugins.pay-kit')
  local status = plugin.access({amount = 'not-decimal', stablecoins = {'USDC'}},
                               {var = {uri = '/'}})
  helper.assert_equal(status, 500)
end)

helper.test('APISIX access with named gate dispatches to dispatcher', function()
  pay_kit._reset_for_tests()
  pay_kit.configure({
    network = 'solana_devnet',
    rpc_url = 'https://api.devnet.solana.com',
    accept  = {'x402', 'mpp'},
    operator = {recipient = 'ApisixRecipient000000000000000000000000000'},
    mpp = {realm = 'APISIX', challenge_binding_secret = 'apx-secret'},
  })
  pay_kit.gate('report', {amount = pay_kit.usd('0.05', 'USDC')})
  local plugin = require('plugins.apisix.plugins.pay-kit')
  local status = plugin.access({gate = 'report'}, {var = {uri = '/report'}})
  helper.assert_equal(status, 402)
end)

helper.test('APISIX header_filter stamps settlement headers onto response', function()
  local plugin = require('plugins.apisix.plugins.pay-kit')
  set_headers = {}
  local ctx = {
    pay_kit_settlement_headers = {
      ['x-payment-settlement-signature'] = 'sig-xyz',
    },
  }
  plugin.header_filter({}, ctx)
  helper.assert_equal(set_headers['x-payment-settlement-signature'], 'sig-xyz')
end)

helper.test('APISIX header_filter no-ops without ctx.pay_kit_settlement_headers', function()
  local plugin = require('plugins.apisix.plugins.pay-kit')
  set_headers = {}
  plugin.header_filter({}, {})
  helper.assert_true(next(set_headers) == nil)
end)

helper.test('APISIX check_schema accepts well-formed config', function()
  local plugin = require('plugins.apisix.plugins.pay-kit')
  helper.assert_true(plugin.check_schema({amount = '0.01', stablecoins = {'USDC'}}))
end)
