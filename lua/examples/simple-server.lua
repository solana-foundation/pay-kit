#!/usr/bin/env luajit
-- Minimal LuaJIT MPP example server.
--
-- Mirrors `ruby/examples/simple-server/app.rb`: a bare TCP loop that
-- gates `/paid` behind an MPP charge and serves `/health` for free.
-- A request without `Authorization: Payment ...` gets a 402 with a
-- signed `WWW-Authenticate` challenge issued by `mpp.server.new`. A
-- well-formed `Authorization: Payment` credential triggers the full
-- Solana settlement lifecycle: parse the wire transaction, cosign
-- with the configured fee payer, simulate, broadcast, consume the
-- signature, and await confirmation. On success the response carries
-- the `Payment-Receipt` header with the on-chain signature.
--
-- Run:
--   cd lua && eval "$(luarocks --lua-version=5.1 --tree lua_modules path)"
--   MPP_FEE_PAYER_SECRET_KEY='[...]' luajit examples/simple-server.lua
-- Then, in another terminal:
--   curl -i http://127.0.0.1:4569/paid       # 402 with WWW-Authenticate
--   pay curl http://127.0.0.1:4569/paid       # 200 with Payment-Receipt
--   curl -i http://127.0.0.1:4569/health     # 200 (unprotected)

local socket = require('socket')
local mpp = require('tests._mpp')
local json = require('pay_kit.util.json')
local headers = require('pay_kit.protocol.core.headers')
local intents = require('pay_kit.protocols.mpp.charge')
local error_codes = require('pay_kit.protocol.core.error_codes')
local solana_verify = require('pay_kit.protocols.mpp.server.solana_verify')
local charge_handler = require('pay_kit.protocols.mpp.server.charge_handler')
local rpc_module = require('pay_kit.solana.rpc')
local rpc_transport = require('pay_kit.solana.rpc_transport')
local signer_module = require('pay_kit.solana.local_signer')
local store_module = require('pay_kit.protocols.mpp.store')

local PORT = tonumber(os.getenv('PORT') or '4569')
local RECIPIENT = os.getenv('MPP_PAY_TO')
  or 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'
local CURRENCY = os.getenv('MPP_CURRENCY') or 'USDC'
local NETWORK = os.getenv('MPP_NETWORK') or 'localnet'
local SECRET = os.getenv('MPP_SECRET_KEY') or 'lua-mpp-dev-secret'
local AMOUNT = os.getenv('MPP_AMOUNT') or '1000'
local RPC_URL = os.getenv('MPP_RPC_URL') or 'https://402.surfnet.dev:8899'
local FEE_PAYER_KEY = os.getenv('MPP_FEE_PAYER_SECRET_KEY')

local rpc = rpc_module.new({ url = RPC_URL, transport = rpc_transport.new() })
local fee_payer = FEE_PAYER_KEY and signer_module.from_json_array(FEE_PAYER_KEY) or nil

-- The real verifier replaces the PR A stub. When no fee-payer secret key is
-- configured the server runs in verify-only mode: it still settles, but
-- callers must pre-cosign the transaction.
local verifier_bundle = solana_verify.new_real_verifier({ pull_signer = fee_payer })

local handler = charge_handler.new({
  rpc = rpc,
  network = NETWORK,
  replay_store = store_module.memory(),
  transaction_verifier = verifier_bundle.transaction_verifier,
  pull_transaction_signer = verifier_bundle.pull_transaction_signer,
  pull_blockhash_extractor = verifier_bundle.pull_blockhash_extractor,
})

local server = mpp.server.new({
  recipient = RECIPIENT,
  currency = CURRENCY,
  decimals = 6,
  network = NETWORK,
  rpc_url = RPC_URL,
  secret_key = SECRET,
  realm = 'Lua MPP Example',
  fee_payer = fee_payer ~= nil,
  fee_payer_key = fee_payer and fee_payer.public_key or nil,
  verify_payment = handler:as_callback(),
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
  local challenge_value = server:charge(AMOUNT)
  write_response(conn, 402, {
    ['content-type'] = 'application/json',
    ['www-authenticate'] = headers.format_www_authenticate(challenge_value),
  }, json.encode({
    error = 'payment required',
    message = 'payment required',
    code = error_codes.CHALLENGE_VERIFICATION_FAILED,
  }))
end

-- 200 / 402 settlement attempt: only reached when an Authorization header is
-- present. The real verifier walks the wire transaction; on success the
-- receipt header carries the on-chain signature for the client to confirm.
-- On failure the response carries a canonical L6 error code so consumers
-- can distinguish charge-request mismatches, network mismatches, and
-- replay rejections without parsing the human message.
local function attempt_settlement(conn, authorization)
  local credential, parse_err = headers.parse_authorization(authorization)
  if not credential then
    write_response(conn, 402, { ['content-type'] = 'application/json' },
      json.encode({
        error = 'invalid authorization',
        message = tostring(parse_err or 'invalid authorization'),
        code = error_codes.CHALLENGE_VERIFICATION_FAILED,
      }))
    return
  end
  local expected_base_units = intents.parse_units(AMOUNT, 6)
  local ok, settlement = pcall(function()
    return server:verify_credential_with_expected(credential, {
      amount = expected_base_units,
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
    if settlement and settlement.reference then
      hdrs[mpp.PaymentReceiptHeader] = headers.format_receipt(settlement)
    end
    write_response(conn, 200, hdrs, json.encode({ ok = true, paid = true }))
  else
    local response = error_codes.to_response(settlement)
    io.stderr:write('settlement failed: ' .. tostring(response.message)
      .. ' (' .. tostring(response.code) .. ')\n')
    io.stderr:flush()
    write_response(conn, 402, { ['content-type'] = 'application/json' },
      json.encode(response))
  end
end

local listener = assert(socket.bind('127.0.0.1', PORT))
listener:settimeout(0.1)
io.stderr:write(string.format(
  'lua simple-server listening on 127.0.0.1:%d (recipient=%s currency=%s network=%s rpc=%s fee_payer=%s)\n',
  PORT, RECIPIENT, CURRENCY, NETWORK, RPC_URL, tostring(fee_payer and fee_payer.public_key or 'none')))
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
