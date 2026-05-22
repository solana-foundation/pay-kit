#!/usr/bin/env luajit
-- Minimal LuaJIT MPP example server.
--
-- Mirrors `ruby/examples/simple-server/app.rb`: a bare TCP loop that
-- gates `/paid` behind an MPP charge and serves `/health` for free.
-- A request without `Authorization: Payment ...` gets a 402 with a
-- signed `WWW-Authenticate` challenge issued by `mpp.server.new`.
--
-- This example does NOT settle on-chain. The Solana stack required
-- for transaction decode + base58 + Ed25519 + ATA derive ships in
-- the follow-up Lua PR B; this file uses a stub `verify_payment`
-- that always rejects so the example demonstrates challenge
-- issuance and credential parsing without claiming settlement
-- support that PR A does not own. Once PR B lands, swap the stub
-- for `mpp.server.solana_verify.new_signature_verifier` and the
-- `pay curl` flow returns 200 with a `payment-receipt` header.
--
-- Run:
--   cd lua && eval "$(luarocks --lua-version=5.1 --tree lua_modules path)"
--   luajit examples/simple-server.lua
-- Then, in another terminal:
--   curl -i http://127.0.0.1:4569/paid       # 402 with WWW-Authenticate
--   curl -i http://127.0.0.1:4569/health     # 200 (unprotected)

local socket = require('socket')
local mpp = require('mpp')
local json = require('mpp.util.json')
local headers = require('mpp.protocol.core.headers')

local PORT = tonumber(os.getenv('PORT') or '4569')
local RECIPIENT = os.getenv('MPP_PAY_TO')
  or 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'
local CURRENCY = os.getenv('MPP_CURRENCY') or 'USDC'
local NETWORK = os.getenv('MPP_NETWORK') or 'localnet'
local SECRET = os.getenv('MPP_SECRET_KEY') or 'lua-mpp-dev-secret'
local AMOUNT = os.getenv('MPP_AMOUNT') or '1000'

-- PR B replaces this stub with `mpp.server.solana_verify.new_signature_verifier`
-- backed by the real base58 / transaction codec / Ed25519 / ATA derive stack.
local function stub_verify_payment(_context)
  error({
    code = 'settlement-deferred',
    message = 'settlement requires the Solana stack landing in PR B; '
            .. 'this example only demonstrates challenge issuance',
  })
end

local server = mpp.server.new({
  recipient = RECIPIENT,
  currency = CURRENCY,
  decimals = 6,
  network = NETWORK,
  secret_key = SECRET,
  realm = 'Lua MPP Example',
  verify_payment = stub_verify_payment,
})

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

-- Write one HTTP response. `body` is a string; `hdrs` is a name->value table.
local function write_response(conn, status, hdrs, body)
  local reason = ({
    [200] = 'OK',
    [402] = 'Payment Required',
    [404] = 'Not Found',
    [500] = 'Internal Server Error',
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

-- 402 builder: issue a fresh signed challenge for `/paid`.
local function payment_required(conn)
  local challenge = server:charge(AMOUNT)
  write_response(conn, 402, {
    ['content-type'] = 'application/json',
    ['www-authenticate'] = headers.format_www_authenticate(challenge),
  }, json.encode({ error = 'payment required' }))
end

-- 200 / 402 settlement attempt: only reached when an Authorization
-- header is present. The stub verifier always raises, so this branch
-- demonstrates the structured-error 402 shape; PR B swaps the stub
-- for the real settler.
local function attempt_settlement(conn, authorization)
  local ok, settlement = pcall(function()
    return server:verify_credential_with_expected(authorization, {
      amount = AMOUNT,
      currency = CURRENCY,
      recipient = RECIPIENT,
    })
  end)
  if ok then
    local hdrs = { ['content-type'] = 'application/json' }
    if settlement and settlement.headers then
      for name, value in pairs(settlement.headers) do
        hdrs[name] = value
      end
    end
    write_response(conn, 200, hdrs,
      json.encode({ ok = true, paid = true }))
  else
    local detail = type(settlement) == 'table' and settlement.message
      or tostring(settlement)
    write_response(conn, 402, { ['content-type'] = 'application/json' },
      json.encode({ error = 'verification failed', detail = detail }))
  end
end

local listener = assert(socket.bind('127.0.0.1', PORT))
listener:settimeout(0.1)
io.stderr:write(string.format(
  'lua simple-server listening on 127.0.0.1:%d (recipient=%s currency=%s network=%s)\n',
  PORT, RECIPIENT, CURRENCY, NETWORK))
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
    write_response(conn, 200,
      { ['content-type'] = 'application/json' },
      json.encode({ ok = true }))
  elseif req.path == '/paid' then
    local auth = req.headers['authorization']
    if not auth or auth == '' then
      payment_required(conn)
    else
      attempt_settlement(conn, auth)
    end
  else
    write_response(conn, 404,
      { ['content-type'] = 'application/json' },
      json.encode({ error = 'not found' }))
  end
  conn:close()
end

while true do
  local ok, err = pcall(handle_one)
  if not ok then
    io.stderr:write('handler error: ' .. tostring(err) .. '\n')
  end
end
