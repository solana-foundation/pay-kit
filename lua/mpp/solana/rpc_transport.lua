--[[
Reference HTTP transport for `mpp.solana.rpc`.

The RPC client deliberately takes the transport as a function so it can
be unit-tested without depending on a network stack. Production callers
need a real HTTP POST implementation, which this module provides through
luasocket (for `http://`) and luasec (for `https://`). Both rocks are
optional at install time; the transport degrades to the available
schemes and raises a clean error if a request needs HTTPS without
luasec being present.

Usage:
  local rpc = require('mpp.solana.rpc').new({
    url = 'https://402.surfnet.dev:8899',
    transport = require('mpp.solana.rpc_transport').new(),
  })
]]

local M = {}

local function load_http()
  local http_ok, http = pcall(require, 'socket.http')
  if not http_ok then
    return nil, 'socket.http is required for HTTP transport: ' .. tostring(http)
  end
  return http
end

local function load_https()
  local https_ok, https = pcall(require, 'ssl.https')
  if not https_ok then
    return nil, 'ssl.https (luasec) is required for HTTPS transport: ' .. tostring(https)
  end
  return https
end

local function load_ltn12()
  local ok, ltn12 = pcall(require, 'ltn12')
  if not ok then
    error('ltn12 is required: ' .. tostring(ltn12))
  end
  return ltn12
end

--- Build a transport function suitable for `mpp.solana.rpc.new({ transport = ... })`.
--- The returned closure accepts `(url, body)` and returns `(response_body)`
--- or raises a transport-error table.
function M.new(opts)
  opts = opts or {}
  local timeout = opts.timeout or 30
  local ltn12 = load_ltn12()
  return function(url, body)
    local sink_buffer = {}
    local request = {
      url = url,
      method = 'POST',
      headers = {
        ['content-type'] = 'application/json',
        ['accept'] = 'application/json',
        ['content-length'] = tostring(#body),
        ['user-agent'] = opts.user_agent or 'mpp-lua/0.1',
      },
      source = ltn12.source.string(body),
      sink = ltn12.sink.table(sink_buffer),
    }
    local result, status_or_err
    if url:sub(1, 6) == 'https:' then
      local https, err = load_https()
      if not https then
        error({ code = 'transport-error', message = err })
      end
      https.TIMEOUT = timeout
      result, status_or_err = https.request(request)
    else
      local http, err = load_http()
      if not http then
        error({ code = 'transport-error', message = err })
      end
      http.TIMEOUT = timeout
      result, status_or_err = http.request(request)
    end
    if result == nil then
      error({
        code = 'transport-error',
        message = 'http request failed: ' .. tostring(status_or_err),
      })
    end
    if type(status_or_err) == 'number' and status_or_err >= 500 then
      error({
        code = 'transport-error',
        message = 'http request returned ' .. tostring(status_or_err),
      })
    end
    return table.concat(sink_buffer)
  end
end

return M
