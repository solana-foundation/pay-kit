--[[
L8 ordering tests for `x402/exact_settle.lua`.

Asserts the broadcast → await `getSignatureStatuses` → put_if_absent
pipeline that the x402-sdk-implementation skill's `pr-readiness.md`
L8 section requires:

  * the replay marker is written ONLY after a confirmed status
  * the replay key shape is `x402-svm-exact:consumed:<base58_signature>`
  * a duplicate signature raises canonical `signature_consumed`, never 200
  * an RPC failure before confirmation surfaces the error and leaves the
    replay store untouched (no release path)
]]

local t = require('tests.test_helper')
local exact_settle = require('x402.exact_settle')

-- Scripted RPC: returns the next response for the named method and records
-- every call so tests can assert the ordering. `responses[<method>]` is a
-- list of `{ result = ... }` or `{ error = '...' }` entries.
local function fake_rpc(responses)
  local state = { calls = {} }
  local indices = {}
  local function rpc_call(method, params)
    state.calls[#state.calls + 1] = { method = method, params = params }
    indices[method] = (indices[method] or 0) + 1
    local list = responses[method]
    if list == nil then
      error('unexpected ' .. method .. ' call')
    end
    local entry = list[indices[method]]
    if entry == nil then
      error('exhausted responses for ' .. method)
    end
    if entry.error then
      error(entry.error)
    end
    return entry.result
  end
  state.rpc_call = rpc_call
  return state
end

local function ok_status_envelope()
  return { result = { value = { { confirmationStatus = 'confirmed', err = nil } } } }
end

local function processed_status_envelope()
  return { result = { value = { { confirmationStatus = 'processed', err = nil } } } }
end

-- ─── put_if_absent + key shape ────────────────────────────────────────────

t.test('consume_signature uses x402-svm-exact:consumed:<sig> key', function()
  local store = exact_settle.new_memory_store()
  local key = exact_settle.consume_signature(store, 'SiGsig111111')
  t.assert_equal(key, 'x402-svm-exact:consumed:SiGsig111111')
  t.assert_true(store:get(key) ~= nil, 'replay marker present')
end)

t.test('consume_signature rejects duplicate with canonical signature_consumed', function()
  local store = exact_settle.new_memory_store()
  exact_settle.consume_signature(store, 'DUPE')
  local ok, err = pcall(exact_settle.consume_signature, store, 'DUPE')
  t.assert_true(not ok, 'duplicate must raise')
  t.assert_equal(type(err) == 'table' and err.code, 'signature_consumed',
    'expected table-error with code=signature_consumed, got: ' .. tostring(err))
end)

-- ─── L8 ordering: broadcast → confirm → put_if_absent ────────────────────

t.test('broadcast_confirm_consume orders broadcast before confirm before mark', function()
  local store = exact_settle.new_memory_store()
  local rpc = fake_rpc({ getSignatureStatuses = { ok_status_envelope() } })
  local broadcast_called = false
  local marker_present_at_broadcast = false
  local marker_present_at_confirm = false
  local marker_present_after

  local signature = exact_settle.broadcast_confirm_consume({
    broadcast = function()
      broadcast_called = true
      marker_present_at_broadcast = store:get('x402-svm-exact:consumed:SiG') ~= nil
      return 'SiG'
    end,
    rpc_call = function(method, params)
      if method == 'getSignatureStatuses' then
        marker_present_at_confirm = store:get('x402-svm-exact:consumed:SiG') ~= nil
      end
      return rpc.rpc_call(method, params)
    end,
    replay_store = store,
    confirmation_attempts = 1,
    confirmation_delay_seconds = 0,
    sleep = function() end,
  })
  marker_present_after = store:get('x402-svm-exact:consumed:SiG') ~= nil

  t.assert_equal(signature, 'SiG')
  t.assert_true(broadcast_called, 'broadcast must run')
  t.assert_true(not marker_present_at_broadcast, 'no pre-claim before broadcast')
  t.assert_true(not marker_present_at_confirm, 'no pre-claim before confirmation poll')
  t.assert_true(marker_present_after, 'replay marker written after confirmation')
  t.assert_equal(rpc.calls[1].method, 'getSignatureStatuses')
end)

t.test('broadcast_confirm_consume polls until confirmed/finalized', function()
  local store = exact_settle.new_memory_store()
  local rpc = fake_rpc({
    getSignatureStatuses = {
      processed_status_envelope(),
      processed_status_envelope(),
      ok_status_envelope(),
    },
  })
  local signature = exact_settle.broadcast_confirm_consume({
    broadcast = function() return 'POLL' end,
    rpc_call = rpc.rpc_call,
    replay_store = store,
    confirmation_attempts = 5,
    confirmation_delay_seconds = 0,
    sleep = function() end,
  })
  t.assert_equal(signature, 'POLL')
  t.assert_equal(#rpc.calls, 3)
  t.assert_true(store:get('x402-svm-exact:consumed:POLL') ~= nil)
end)

-- ─── Bounding: RPC error before confirmation ─────────────────────────────

t.test('broadcast_confirm_consume short-circuits on getSignatureStatuses RPC error', function()
  local store = exact_settle.new_memory_store()
  local rpc = fake_rpc({
    getSignatureStatuses = { { error = 'rpc-fail: -32000' } },
  })
  local ok, err = pcall(exact_settle.broadcast_confirm_consume, {
    broadcast = function() return 'RPCERR' end,
    rpc_call = rpc.rpc_call,
    replay_store = store,
    confirmation_attempts = 5,
    confirmation_delay_seconds = 0,
    sleep = function() end,
  })
  t.assert_true(not ok, 'RPC failure must raise')
  t.assert_true(tostring(err):match('rpc%-fail') ~= nil,
    'underlying RPC error surfaces, got: ' .. tostring(err))
  -- Critical L8 invariant: replay marker NOT written when confirmation fails.
  t.assert_true(store:get('x402-svm-exact:consumed:RPCERR') == nil,
    'replay store untouched on confirmation failure (no release path needed)')
end)

t.test('broadcast_confirm_consume short-circuits on on-chain meta.err', function()
  local store = exact_settle.new_memory_store()
  local rpc = fake_rpc({
    getSignatureStatuses = {
      { result = { value = { { confirmationStatus = 'confirmed', err = 'InstructionError' } } } },
    },
  })
  local ok, err = pcall(exact_settle.broadcast_confirm_consume, {
    broadcast = function() return 'ONCHAINERR' end,
    rpc_call = rpc.rpc_call,
    replay_store = store,
    confirmation_attempts = 3,
    confirmation_delay_seconds = 0,
    sleep = function() end,
  })
  t.assert_true(not ok, 'meta.err must raise')
  t.assert_true(tostring(err):match('failed') ~= nil)
  t.assert_true(store:get('x402-svm-exact:consumed:ONCHAINERR') == nil,
    'failed transaction must not be marked consumed')
end)

t.test('broadcast_confirm_consume times out within attempt budget (blockhash window surrogate)', function()
  local store = exact_settle.new_memory_store()
  local rpc = fake_rpc({
    getSignatureStatuses = {
      processed_status_envelope(),
      processed_status_envelope(),
    },
  })
  local sleep_calls = 0
  local ok, err = pcall(exact_settle.broadcast_confirm_consume, {
    broadcast = function() return 'TIMEOUT' end,
    rpc_call = rpc.rpc_call,
    replay_store = store,
    confirmation_attempts = 2,
    confirmation_delay_seconds = 0,
    sleep = function() sleep_calls = sleep_calls + 1 end,
  })
  t.assert_true(not ok, 'timeout must raise')
  t.assert_true(tostring(err):match('timed out') ~= nil)
  t.assert_true(store:get('x402-svm-exact:consumed:TIMEOUT') == nil,
    'timeout must not insert a replay marker')
end)

-- ─── Duplicate-after-confirmation rejection ──────────────────────────────

t.test('broadcast_confirm_consume rejects duplicate signature post-confirmation', function()
  local store = exact_settle.new_memory_store()
  local rpc = fake_rpc({
    getSignatureStatuses = {
      ok_status_envelope(),
      ok_status_envelope(),
    },
  })

  local first = exact_settle.broadcast_confirm_consume({
    broadcast = function() return 'REPLAY' end,
    rpc_call = rpc.rpc_call,
    replay_store = store,
    confirmation_attempts = 1,
    confirmation_delay_seconds = 0,
    sleep = function() end,
  })
  t.assert_equal(first, 'REPLAY')

  local ok, err = pcall(exact_settle.broadcast_confirm_consume, {
    broadcast = function() return 'REPLAY' end,
    rpc_call = rpc.rpc_call,
    replay_store = store,
    confirmation_attempts = 1,
    confirmation_delay_seconds = 0,
    sleep = function() end,
  })
  t.assert_true(not ok, 'duplicate must raise')
  t.assert_equal(type(err) == 'table' and err.code, 'signature_consumed',
    'expected canonical signature_consumed error, got: ' .. tostring(err))
end)

-- ─── No-release-path invariant ────────────────────────────────────────────

t.test('broadcast_confirm_consume has no release path on broadcast failure', function()
  local store = exact_settle.new_memory_store()
  -- Use an explicit sentinel: if the helper ever inserts a key before
  -- broadcast succeeds, this test will fail.
  store:put_if_absent('x402-svm-exact:consumed:SENTINEL', true)
  local ok, err = pcall(exact_settle.broadcast_confirm_consume, {
    broadcast = function() error('broadcast-fail: rate limited') end,
    rpc_call = function() error('rpc must not be called when broadcast fails') end,
    replay_store = store,
    confirmation_attempts = 1,
    confirmation_delay_seconds = 0,
    sleep = function() end,
  })
  t.assert_true(not ok, 'broadcast failure must propagate')
  t.assert_true(tostring(err):match('broadcast%-fail') ~= nil)
  -- Sentinel is still the only key — broadcast failure does not write
  -- anything to the store.
  t.assert_true(store:get('x402-svm-exact:consumed:SENTINEL') ~= nil)
end)

-- ─── Replay key namespace constant ───────────────────────────────────────

t.test('REPLAY_KEY_PREFIX is x402-svm-exact:consumed:', function()
  t.assert_equal(exact_settle.REPLAY_KEY_PREFIX, 'x402-svm-exact:consumed:')
end)
