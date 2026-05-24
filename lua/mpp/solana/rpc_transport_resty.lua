--[[
Non-blocking HTTP transport for `mpp.solana.rpc`, intended for use
inside the OpenResty / Kong access phase.

The companion `mpp.solana.rpc_transport` module uses `socket.http` /
`ssl.https` from LuaSocket / LuaSec, which are synchronous, OS-thread
blocking calls. Running them inside an nginx worker would block the
entire worker for the full RPC round trip and starve every other
in-flight request on that worker. Codex PR #103 review flagged this
as a P1 worker-starvation risk.

This module uses `lua-resty-http` on top of nginx cosockets, which
suspend the current Lua coroutine on I/O and yield back to the event
loop. Concurrent requests on the same worker continue to make
progress while the Solana RPC call is in flight.

Usage (inside an OpenResty / Kong context, after declaring
`lua_shared_dict` for the replay store):

  local rpc = require('mpp.solana.rpc').new({
    url = 'https://api.mainnet-beta.solana.com',
    transport = require('mpp.solana.rpc_transport_resty').new(),
  })

`resty.http` is shipped by `lua-resty-http`
(https://github.com/ledgetech/lua-resty-http). It is bundled with
OpenResty distributions; on bare nginx-with-Lua install with
`luarocks install lua-resty-http`.
]]

local M = {}

local function load_resty_http()
  local ok, http = pcall(require, 'resty.http')
  if not ok then
    return nil, 'resty.http is required for the cosocket transport: ' .. tostring(http)
  end
  return http
end

local function in_cosocket_context()
  -- `ngx.get_phase` returns the current nginx request phase. Cosocket
  -- operations are legal in rewrite/access/content/timer phases; the
  -- init / init_worker phases are not cosocket-safe. The transport is
  -- documented for `access`, which is the Kong plugin's phase.
  if not ngx or not ngx.get_phase then
    return false
  end
  local phase = ngx.get_phase()
  return phase == 'rewrite' or phase == 'access'
    or phase == 'content' or phase == 'timer'
    or phase == 'ssl_cert' or phase == 'ssl_session_fetch'
end

--- Build a transport function suitable for `mpp.solana.rpc.new({ transport = ... })`.
-- The returned closure accepts `(url, body)` and returns the response body
-- string, or raises a typed transport-error table matching the surface of
-- `mpp.solana.rpc_transport`.
--
-- `opts.timeout` is in seconds (matching the blocking transport). It is
-- applied to connect / send / read via `set_timeouts`.
-- `opts.keepalive_pool_size` and `opts.keepalive_idle_ms` control the
-- per-worker connection pool. Defaults mirror lua-resty-http upstream.
function M.new(opts)
  opts = opts or {}
  local timeout_ms = math.floor((opts.timeout or 30) * 1000)
  local user_agent = opts.user_agent or 'mpp-lua/0.1'
  local keepalive_pool = opts.keepalive_pool_size or 32
  local keepalive_idle = opts.keepalive_idle_ms or 60000
  local ssl_verify = opts.ssl_verify
  if ssl_verify == nil then
    ssl_verify = true
  end

  return function(url, body)
    if not in_cosocket_context() then
      error({
        code = 'transport-error',
        message = 'resty transport must run in a cosocket-capable phase '
          .. '(rewrite/access/content/timer); current phase is '
          .. tostring(ngx and ngx.get_phase and ngx.get_phase() or 'no-ngx'),
      })
    end
    local http, load_err = load_resty_http()
    if not http then
      error({ code = 'transport-error', message = load_err })
    end
    local client, new_err = http.new()
    if not client then
      error({ code = 'transport-error', message = 'resty.http new failed: ' .. tostring(new_err) })
    end
    client:set_timeouts(timeout_ms, timeout_ms, timeout_ms)
    local res, req_err = client:request_uri(url, {
      method = 'POST',
      body = body,
      headers = {
        ['content-type'] = 'application/json',
        ['accept'] = 'application/json',
        ['content-length'] = tostring(#body),
        ['user-agent'] = user_agent,
      },
      ssl_verify = ssl_verify,
      keepalive_timeout = keepalive_idle,
      keepalive_pool = keepalive_pool,
    })
    if not res then
      error({
        code = 'transport-error',
        message = 'http request failed: ' .. tostring(req_err),
      })
    end
    if type(res.status) == 'number' and res.status >= 500 then
      error({
        code = 'transport-error',
        message = 'http request returned ' .. tostring(res.status),
      })
    end
    return res.body or ''
  end
end

return M
