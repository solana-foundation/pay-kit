--[[
P6 replay store. Pure-Lua suite exercises the in-memory backend;
shared_dict path is exercised by the existing
`tests.store_shared_dict_spec` against the legacy mpp surface.
]]

local helper = require('tests.test_helper')
local store_mod = require('resty.pay_kit.store')

helper.test('memory store put_if_absent returns true on first call', function()
  local s = store_mod.memory()
  helper.assert_equal(s:put_if_absent('k', 60), true)
end)

helper.test('memory store put_if_absent returns false on duplicate', function()
  local s = store_mod.memory()
  s:put_if_absent('k', 60)
  helper.assert_equal(s:put_if_absent('k', 60), false)
end)

helper.test('memory store get returns true after put', function()
  local s = store_mod.memory()
  s:put_if_absent('k', 60)
  helper.assert_equal(s:get('k'), true)
end)

helper.test('memory store delete removes the key', function()
  local s = store_mod.memory()
  s:put_if_absent('k', 60)
  s:delete('k')
  helper.assert_equal(s:get('k'), false)
end)

helper.test('detect() returns memory backend when ngx absent', function()
  local s, backend = store_mod.detect({warn_on_fallback = false})
  -- In the test harness ngx is nil so we land on memory.
  helper.assert_equal(backend, 'memory')
  helper.assert_true(s.put_if_absent ~= nil)
end)
