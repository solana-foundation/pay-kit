--[[
ngx.shared.DICT-backed replay store for OpenResty / Kong multi-worker
safety.

A Kong deployment with default `worker_processes auto` runs one Lua
state per CPU core. The in-memory `mpp.store.memory()` store is per-Lua
state, so a signature consumed by Worker A is invisible to Workers B,
C, etc. An attacker who receives a valid Payment-Receipt can replay the
same Authorization: Payment header against a different worker and obtain
another 200 OK with a fresh on-chain settlement. This module fixes that
by routing every consume / lookup through an `ngx.shared.DICT` instance
that lives in nginx-managed shared memory and is visible to every worker.

The DICT's `:add(key, value [, exptime])` method is the canonical
atomic-on-collision primitive in OpenResty: it returns `(true)` on first
insert and `(false, "exists")` on a duplicate. We use that for
`put_if_absent`, which is the single replay-store contract the server
and charge handler rely on. Plain `:set()` would silently overwrite the
previous value and lose the duplicate-detection signal; the audit row
specifically calls this out as the trap to avoid.

Usage in a Kong handler / OpenResty access phase:

  -- nginx.conf:    lua_shared_dict mpp_replay 10m;
  local dict = ngx.shared.mpp_replay
  local replay_store = require('mpp.server.store_shared_dict').new(dict)
  -- Then pass `replay_store` to both mpp.server.new({store = ...})
  -- and mpp.server.charge_handler.new({replay_store = ...}) so the two
  -- replay surfaces share the same cross-worker view.

The store deliberately serializes values with the same `mpp.util.json`
helper the in-memory store uses, so callers can swap implementations
without touching the value shapes they store. Shared dict size and TTL
are owner-controlled because they vary with deployment shape (10MB and
no TTL is the simple-server default; large deployments should size by
expected QPS * challenge_lifetime).
]]

local json = require('mpp.util.json')

local SharedDictStore = {}
SharedDictStore.__index = SharedDictStore

local M = {}

--- Construct a new shared-dict store. `dict` must be the
--- `ngx.shared.<name>` table OpenResty exposes after the matching
--- `lua_shared_dict <name> <size>` directive at the http-block level.
--- `opts.ttl_seconds` is forwarded to `dict:add` as the expiry; the
--- default of zero means "no expiry" (the dict's LRU eviction takes
--- over when the shared memory zone fills up).
function M.new(dict, opts)
  if type(dict) ~= 'table' then
    error('shared dict handle is required (typically ngx.shared.mpp_replay)')
  end
  if type(dict.add) ~= 'function' or type(dict.get) ~= 'function' then
    error('shared dict handle is missing the :add / :get API')
  end
  opts = opts or {}
  return setmetatable({
    dict = dict,
    ttl_seconds = opts.ttl_seconds or 0,
  }, SharedDictStore)
end

--- Read the value at `key`. Returns `(value, true)` on hit and
--- `(nil, false)` on miss. Mirrors the MemoryStore signature.
function SharedDictStore:get(key)
  local raw = self.dict:get(key)
  if raw == nil then
    return nil, false
  end
  return json.decode(raw), true
end

--- Write `value` at `key` unconditionally. Used by the receipt-store
--- path and tests; callers that need duplicate-detection use
--- `put_if_absent` instead.
function SharedDictStore:put(key, value)
  self.dict:set(key, json.encode(value))
end

--- Delete the entry at `key`. Mirrors the MemoryStore API; the server
--- core does not currently call this but keeps the interface
--- symmetrical.
function SharedDictStore:delete(key)
  self.dict:delete(key)
end

--- Atomic insert-if-absent. Returns `true` on first insert,
--- `false` if a value already exists at `key`. Built on the dict's
--- `:add` primitive which is atomic across workers; using plain
--- `:set` here would silently overwrite the previous value and
--- defeat the replay-detection invariant the rest of the server
--- relies on.
function SharedDictStore:put_if_absent(key, value)
  local ok, err = self.dict:add(key, json.encode(value), self.ttl_seconds)
  if ok then
    return true
  end
  -- nginx ngx_shared returns "exists" for the collision case; any
  -- other error (no memory, value too large) gets surfaced so the
  -- caller can react. Production deployments size the dict large
  -- enough that "no memory" should not happen at runtime; if it
  -- does, the consume path raises and the request fails closed.
  if err == 'exists' then
    return false
  end
  error('shared dict put_if_absent failed: ' .. tostring(err))
end

M.SharedDictStore = SharedDictStore

return M
