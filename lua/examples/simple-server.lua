#!/usr/bin/env luajit
-- Minimal LuaJIT PayKit example server (no OpenResty).
--
-- A bare TCP loop that gates `/paid` behind a stablecoin charge through
-- the `pay_kit` umbrella and serves `/health` for free. This is the
-- host-agnostic counterpart to examples/nginx/: same one-surface API,
-- driven from a raw socket instead of an nginx access phase.
--
-- The umbrella's `try_payment(name, req)` never halts; it hands back
-- (payment, err, response) so a non-OpenResty host can render the 402
-- itself. A request without a credential gets a 402 with the signed
-- challenge headers; a valid `Authorization: Payment` credential runs
-- the full Solana settlement lifecycle and the 200 carries the
-- settlement headers (the on-chain signature).
--
-- Sensible defaults: with no environment set, configure() boots against
-- solana_localnet (the hosted Surfpool clone at https://402.surfnet.dev:8899)
-- with the published demo signer as operator + recipient.
--
-- Run:
--   cd lua && eval "$(luarocks --lua-version=5.1 --tree lua_modules path)"
--   luajit examples/simple-server.lua
-- Then, in another terminal:
--   curl -i http://127.0.0.1:4569/health     # 200 (unprotected)
--   curl -i http://127.0.0.1:4569/paid       # 402 with WWW-Authenticate
--   pay curl http://127.0.0.1:4569/paid      # 200 with the protected payload

local socket  = require('socket')
local pay_kit = require('pay_kit')
local cjson   = require('cjson.safe')

local PORT = tonumber(os.getenv('PORT') or '4569')

assert(pay_kit.configure({
  network     = 'solana_localnet',
  accept      = { 'x402', 'mpp' },
  stablecoins = { 'USDC' },
  mpp         = { realm = 'Lua PayKit Example', expires_in = 300 },
}))

pay_kit.gate('paid', { amount = pay_kit.usd('0.10') })

-- Read one HTTP request from a TCP socket. Returns { method, path, headers }.
local function read_request(conn)
  local line, err = conn:receive('*l')
  if not line then return nil, err end
  local method, raw_path = line:match('^(%S+)%s+(%S+)%s+HTTP/')
  if not method then return nil, 'bad request line' end
  local hdrs = {}
  while true do
    local h
    h, err = conn:receive('*l')
    if not h then return nil, err end
    if h == '' then break end
    local name, value = h:match('^([^:]+):%s*(.*)$')
    if name then hdrs[name:lower()] = value end
  end
  return { method = method, path = raw_path, headers = hdrs }
end

local function write_response(conn, status, hdrs, body)
  local reason = ({
    [200] = 'OK',
    [402] = 'Payment Required',
    [404] = 'Not Found',
  })[status] or 'OK'
  local parts = { 'HTTP/1.1 ' .. status .. ' ' .. reason }
  hdrs = hdrs or {}
  hdrs['content-length'] = tostring(#body)
  hdrs['connection'] = 'close'
  for name, value in pairs(hdrs) do
    parts[#parts + 1] = name .. ': ' .. value
  end
  parts[#parts + 1] = ''
  parts[#parts + 1] = body
  conn:send(table.concat(parts, '\r\n'))
end

-- Gate `/paid` through the umbrella. On success the verified payment
-- carries the settlement headers; on failure the response table holds
-- the 402 challenge headers + canonical error body.
local function serve_paid(conn, req)
  local payment, _err, response = pay_kit.try_payment('paid', {
    headers = req.headers, path = req.path, query = {},
  })
  if payment then
    local hdrs = { ['content-type'] = 'application/json' }
    for name, value in pairs(payment.settlement_headers or {}) do
      hdrs[name] = value
    end
    write_response(conn, 200, hdrs, cjson.encode({ ok = true, paid = true }))
    return
  end
  local hdrs = { ['content-type'] = 'application/json' }
  for name, value in pairs((response and response.headers) or {}) do
    hdrs[name] = value
  end
  write_response(conn, 402, hdrs,
    cjson.encode((response and response.body) or { error = 'payment_required' }))
end

local listener = assert(socket.bind('127.0.0.1', PORT))
listener:settimeout(0.1)
io.stderr:write(string.format(
  'lua simple-server listening on 127.0.0.1:%d (network=solana_localnet, demo signer)\n', PORT))
io.stderr:flush()

local function handle_one()
  local conn = listener:accept()
  if not conn then return end
  conn:settimeout(2)
  local req = read_request(conn)
  if not req then
    conn:close()
    return
  end
  if req.path == '/health' then
    write_response(conn, 200, { ['content-type'] = 'application/json' },
      cjson.encode({ ok = true }))
  elseif req.path == '/paid' then
    serve_paid(conn, req)
  else
    write_response(conn, 404, { ['content-type'] = 'application/json' },
      cjson.encode({ error = 'not found' }))
  end
  conn:close()
end

while true do
  local ok, err = pcall(handle_one)
  if not ok then
    io.stderr:write('handler error: ' .. tostring(err) .. '\n')
  end
end
