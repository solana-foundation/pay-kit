-- Regression for the OpenResty / Kong cross-worker replay store.
--
-- Greptile P1 on PR #103 flagged that the Kong plugin example built
-- its replay store with `mpp.store.memory()`, which is per-Lua-state.
-- Under Kong's default `worker_processes auto`, a credential consumed
-- by Worker A would be invisible to Workers B, C, etc., letting an
-- attacker replay a consumed Payment credential against a different
-- worker and obtain another 200 OK with a fresh on-chain settlement.
--
-- The fix is `lua/mpp/server/store_shared_dict.lua`, which wraps
-- `ngx.shared.DICT` and routes put_if_absent through the atomic-on-
-- collision `:add` primitive. This spec mocks the shared-dict surface
-- with an in-memory table that mimics the worker-shared semantics
-- (one backing store, multiple store handles), and asserts:
--
-- 1. put_if_absent returns true on first insert.
-- 2. put_if_absent returns false on second insert with the same key.
-- 3. Two store handles pointing at the same fake dict share state
--    (so a consume on Worker A is visible to Worker B).
-- 4. Non-collision errors raise rather than silently returning false.

local t = require('tests.test_helper')
local store_shared_dict = require('mpp.server.store_shared_dict')

-- Fake `ngx.shared.<name>` instance. The real implementation lives
-- inside nginx's shared memory zone; the test fake keeps a single
-- table, plus a hook so we can simulate the no-memory error path.
local function fake_dict(initial_error)
  local backing = {}
  return {
    backing = backing,
    pending_error = initial_error,
    get = function(self, key)
      return backing[key]
    end,
    set = function(self, key, value)
      backing[key] = value
      return true
    end,
    add = function(self, key, value, _ttl_seconds)
      if self.pending_error then
        local err = self.pending_error
        self.pending_error = nil
        return false, err
      end
      if backing[key] ~= nil then
        return false, 'exists'
      end
      backing[key] = value
      return true
    end,
    delete = function(self, key)
      backing[key] = nil
      return true
    end,
  }
end

t.test('store_shared_dict put_if_absent returns true on first insert', function()
  local dict = fake_dict()
  local store = store_shared_dict.new(dict)
  t.assert_equal(store:put_if_absent('sig-1', true), true)
end)

t.test('store_shared_dict put_if_absent returns false on a duplicate insert', function()
  local dict = fake_dict()
  local store = store_shared_dict.new(dict)
  store:put_if_absent('sig-2', true)
  t.assert_equal(store:put_if_absent('sig-2', true), false)
end)

t.test('store_shared_dict shares state across handles pointing at the same dict', function()
  -- Simulates Worker A's handle and Worker B's handle: two store
  -- instances, one backing dict, the same consumed-signature view.
  local dict = fake_dict()
  local worker_a = store_shared_dict.new(dict)
  local worker_b = store_shared_dict.new(dict)
  t.assert_equal(worker_a:put_if_absent('sig-shared', true), true)
  -- Worker B sees the consumed sig and the second put_if_absent
  -- returns false; without the shared dict, both workers would see
  -- an empty replay store and both would accept the duplicate.
  t.assert_equal(worker_b:put_if_absent('sig-shared', true), false)
end)

t.test('store_shared_dict get returns nil and false on a miss', function()
  local dict = fake_dict()
  local store = store_shared_dict.new(dict)
  local value, hit = store:get('missing')
  t.assert_equal(value, nil)
  t.assert_equal(hit, false)
end)

t.test('store_shared_dict raises on non-collision errors (no memory)', function()
  local dict = fake_dict('no memory')
  local store = store_shared_dict.new(dict)
  local ok, err = pcall(function()
    store:put_if_absent('sig-oom', true)
  end)
  t.assert_equal(ok, false)
  t.assert_equal(string.find(tostring(err), 'no memory', 1, true) ~= nil, true)
end)

t.test('store_shared_dict rejects a non-table dict handle', function()
  local ok, err = pcall(function()
    store_shared_dict.new(nil)
  end)
  t.assert_equal(ok, false)
  t.assert_equal(string.find(tostring(err), 'shared dict handle is required', 1, true) ~= nil, true)
end)

t.test('store_shared_dict rejects a dict handle missing add or get', function()
  local ok, err = pcall(function()
    store_shared_dict.new({})
  end)
  t.assert_equal(ok, false)
  t.assert_equal(string.find(tostring(err), 'add / :get', 1, true) ~= nil, true)
end)
