--[[
Replay store backends.

Two backends, picked at dispatcher construction time:

1. `ngx.shared.pay_kit_replay` (preferred): cross-worker shared
   dictionary declared in nginx.conf via
   `lua_shared_dict pay_kit_replay 10m`. Atomic add/get across all
   workers. Kong / APISIX operators add the directive via
   `KONG_NGINX_HTTP_LUA_SHARED_DICT="pay_kit_replay 10m"` or
   `nginx_http_lua_shared_dict = pay_kit_replay 10m`.

2. In-memory LRU (fallback): per-worker table with TTL pruning.
   Useful for single-worker dev setups and tests; logs a warning
   at dispatcher boot so the choice is visible.

Both backends expose the same surface:
- `:put_if_absent(key, ttl)`     -> true on first put, false on duplicate.
                                    A numeric `ttl` (or nil, the default)
                                    expires the entry; any other value
                                    (`true`) is kept with no expiry, the
                                    `(key, value)` contract durable records
                                    such as `pay_kit.consumed_signatures`
                                    rely on.
- `:get(key)`                    -> truthy if present
- `:delete(key)`                 -> nil
]]

local M = {}

local DEFAULT_TTL_SECONDS = 300
local DEFAULT_DICT_NAME   = 'pay_kit_replay'
local MAX_MEMORY_ENTRIES  = 10000

local SharedDict = {}
SharedDict.__index = SharedDict

-- Seconds until an entry written with `ttl` expires, or nil for a durable
-- entry (a non-numeric value).
local function expiry_seconds(ttl)
  if ttl == nil then return DEFAULT_TTL_SECONDS end
  if type(ttl) == 'number' then return ttl end
  return nil
end

function SharedDict:put_if_absent(key, ttl)
  local seconds = expiry_seconds(ttl)
  local ok, err
  if seconds == nil then
    -- Durable: never expires, and `safe_add` refuses rather than evicting
    -- other entries when the zone is full, so a claim is never silently
    -- dropped (a full zone reads as a duplicate, which fails closed).
    ok, err = self._dict:safe_add(key, true, 0)
  else
    ok, err = self._dict:add(key, true, seconds)
  end
  if ok then return true end
  -- `exists` error code means the key was already present.
  if err == 'exists' then return false end
  return false
end

function SharedDict:get(key)
  return self._dict:get(key) ~= nil
end

function SharedDict:delete(key)
  self._dict:delete(key)
end

local Memory = {}
Memory.__index = Memory

function Memory:_prune(now)
  if self._size <= MAX_MEMORY_ENTRIES then return end
  -- Drop entries whose ttl expired. If we still have too many,
  -- continue dropping in insertion order (rough LRU; sufficient for
  -- the dev fallback).
  local kept = {}
  local count = 0
  for k, exp in pairs(self._entries) do
    if exp >= now then kept[k] = exp; count = count + 1 end
  end
  if count > MAX_MEMORY_ENTRIES then
    -- Sort by expiry and drop oldest. Durable entries (math.huge) are
    -- never evicted: dropping a consumed-signature claim would reopen it.
    local arr = {}
    for k, exp in pairs(kept) do
      if exp ~= math.huge then arr[#arr + 1] = {k, exp} end
    end
    table.sort(arr, function(a, b) return a[2] < b[2] end)
    for i = 1, math.min(#arr, count - MAX_MEMORY_ENTRIES) do
      kept[arr[i][1]] = nil
      count = count - 1
    end
  end
  self._entries = kept
  self._size    = count
end

function Memory:put_if_absent(key, ttl)
  local now = os.time()
  self:_prune(now)
  local existing = self._entries[key]
  if existing and existing >= now then return false end
  local seconds = expiry_seconds(ttl)
  self._entries[key] = seconds and (now + seconds) or math.huge
  if not existing then self._size = self._size + 1 end
  return true
end

function Memory:get(key)
  local exp = self._entries[key]
  if not exp then return false end
  if exp < os.time() then
    self._entries[key] = nil
    self._size = self._size - 1
    return false
  end
  return true
end

function Memory:delete(key)
  if self._entries[key] then
    self._entries[key] = nil
    self._size = self._size - 1
  end
end

-- Build a replay store. Auto-detects ngx.shared.pay_kit_replay when
-- ngx is available; otherwise returns the in-memory LRU. The
-- `warn_on_fallback` flag (true by default) emits a log message
-- when the LRU path is picked - operators want to see this.
function M.detect(opts)
  opts = opts or {}
  local dict_name = opts.dict_name or DEFAULT_DICT_NAME
  local ngx_ref = rawget(_G, 'ngx')
  if ngx_ref and ngx_ref.shared and ngx_ref.shared[dict_name] then
    return setmetatable({_dict = ngx_ref.shared[dict_name]}, SharedDict), 'shared_dict'
  end
  if opts.warn_on_fallback ~= false and ngx_ref and ngx_ref.log and ngx_ref.WARN then
    ngx_ref.log(ngx_ref.WARN,
      'pay_kit: lua_shared_dict ' .. dict_name .. ' not declared; ' ..
      'falling back to per-worker in-memory replay store (replay can leak ' ..
      'across workers in production)')
  end
  return setmetatable({_entries = {}, _size = 0}, Memory), 'memory'
end

-- Construct the in-memory backend (skips the ngx probe). Useful for
-- single-worker dev setups and pure-Lua hosts; the dispatcher prefers
-- `detect()` so production OpenResty deployments land on the shared
-- dict automatically.
function M.memory()
  return setmetatable({_entries = {}, _size = 0}, Memory)
end

-- Construct a shared-dict-backed store explicitly. Public surface per
-- issue #140 Layers: `pay_kit.store.shared_dict("name")`.
-- Errors if ngx is not available or the named dict was not declared
-- in nginx.conf via `lua_shared_dict <name> <size>`.
function M.shared_dict(name)
  if type(name) ~= 'string' or name == '' then
    return nil, 'pay_kit: store.shared_dict expects a dict name'
  end
  local ngx_ref = rawget(_G, 'ngx')
  if not ngx_ref or not ngx_ref.shared then
    return nil, 'pay_kit: store.shared_dict requires OpenResty (ngx.shared)'
  end
  local dict = ngx_ref.shared[name]
  if not dict then
    return nil, 'pay_kit: shared dict ' .. name .. ' not declared in nginx.conf'
  end
  return setmetatable({_dict = dict}, SharedDict)
end

return M
