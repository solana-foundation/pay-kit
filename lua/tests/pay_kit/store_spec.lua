--[[
P6 replay store. Pure-Lua suite exercises the in-memory backend;
shared_dict path is exercised by the existing
`tests.store_shared_dict_spec` against the legacy mpp surface.
]]

local helper = require('tests.test_helper')
local store_mod = require('pay_kit.store')

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
  helper.assert_equal(backend, 'memory')
  helper.assert_true(s.put_if_absent ~= nil)
end)

helper.test('memory store expired TTL re-allows put_if_absent', function()
  local s = store_mod.memory()
  s:put_if_absent('k', -1)
  helper.assert_equal(s:put_if_absent('k', 60), true)
end)

helper.test('memory store get drops expired entries', function()
  local s = store_mod.memory()
  s:put_if_absent('k', -1)
  helper.assert_equal(s:get('k'), false)
  helper.assert_equal(s:put_if_absent('k', 60), true)
end)

helper.test('memory store delete on unknown key is a no-op', function()
  local s = store_mod.memory()
  s:delete('never-existed')
  helper.assert_equal(s:get('never-existed'), false)
end)

helper.test('memory store delete after put drops the entry', function()
  local s = store_mod.memory()
  s:put_if_absent('to-drop', 60)
  s:delete('to-drop')
  helper.assert_equal(s:get('to-drop'), false)
  helper.assert_equal(s:put_if_absent('to-drop', 60), true)
end)

helper.test('shared_dict() rejects empty name', function()
  local s, err = store_mod.shared_dict('')
  helper.assert_true(s == nil)
  helper.assert_true(tostring(err):find('expects a dict name', 1, true) ~= nil)
end)

helper.test('shared_dict() rejects non-string name', function()
  local s, err = store_mod.shared_dict(42)
  helper.assert_true(s == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('shared_dict() errors when ngx is absent', function()
  local s, err = store_mod.shared_dict('pay_kit_replay')
  helper.assert_true(s == nil)
  helper.assert_true(tostring(err):find('OpenResty', 1, true) ~= nil)
end)

helper.test('shared_dict() errors when named dict not declared', function()
  local saved = rawget(_G, 'ngx')
  rawset(_G, 'ngx', {shared = {}})
  local s, err = store_mod.shared_dict('missing_dict')
  rawset(_G, 'ngx', saved)
  helper.assert_true(s == nil)
  helper.assert_true(tostring(err):find('not declared', 1, true) ~= nil)
end)

helper.test('detect() picks shared_dict when ngx.shared has the dict', function()
  local saved = rawget(_G, 'ngx')
  local fake = {
    add    = function() return true end,
    get    = function() return nil end,
    delete = function() end,
  }
  rawset(_G, 'ngx', {shared = {pay_kit_replay = fake}})
  local s, backend = store_mod.detect({warn_on_fallback = false})
  rawset(_G, 'ngx', saved)
  helper.assert_equal(backend, 'shared_dict')
  helper.assert_equal(s:put_if_absent('k', 60), true)
end)

helper.test('shared_dict backend round-trips put/get/delete via stub', function()
  local saved = rawget(_G, 'ngx')
  local seen = {}
  local fake = {
    add = function(_, key)
      if seen[key] then return false, 'exists' end
      seen[key] = true
      return true
    end,
    get    = function(_, key) return seen[key] and true or nil end,
    delete = function(_, key) seen[key] = nil end,
  }
  rawset(_G, 'ngx', {shared = {pay_kit_replay = fake}})
  local s = store_mod.detect({warn_on_fallback = false})
  rawset(_G, 'ngx', saved)
  helper.assert_equal(s:put_if_absent('one'), true)
  helper.assert_equal(s:put_if_absent('one'), false)
  helper.assert_equal(s:get('one'), true)
  s:delete('one')
  helper.assert_equal(s:get('one'), false)
end)
