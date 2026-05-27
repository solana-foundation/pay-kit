--[[
P9 APISIX plugin smoke. APISIX plugin loads `apisix.core`, which is
not on the test machine, so we stub the minimum surface to keep the
unit test self-contained.
]]

local helper = require('tests.test_helper')

-- Minimum stub for apisix.core. Mirrors what the plugin imports.
package.loaded['apisix.core'] = {
  log = {error = function() end, warn = function() end, info = function() end},
  schema = {check = function() return true end},
  request = {
    headers       = function() return {} end,
    get_uri_args  = function() return {} end,
  },
  response = {set_header = function() end},
}

helper.test('APISIX plugin exposes the expected shape', function()
  local mod = require('plugins.apisix.plugins.pay-kit')
  helper.assert_equal(type(mod.version), 'number')
  helper.assert_equal(type(mod.priority), 'number')
  helper.assert_equal(mod.name, 'pay-kit')
  helper.assert_equal(type(mod.access), 'function')
  helper.assert_equal(type(mod.header_filter), 'function')
  helper.assert_equal(type(mod.check_schema), 'function')
  helper.assert_true(type(mod.schema) == 'table')
end)
