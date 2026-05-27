#!/usr/bin/env luajit
-- Cross-language harness adapter for the Lua PayKit umbrella.
--
-- One TCP server, two settle paths (x402:exact and mpp:charge), picked
-- per scenario by which env namespace the harness orchestrator sets
-- (or by the explicit PAY_KIT_INTEROP_PROTOCOL hint). Mirrors the
-- Ruby pay-kit-server pattern at harness/ruby-server/server.rb.
--
-- Drives the harness contract:
--   1. Read env (PAY_KIT_INTEROP_PROTOCOL OR exclusive MPP_/X402_).
--   2. configure() + register one gate at the requested amount.
--   3. Listen on a free TCP port; print {"type":"ready",...} on stdout.
--   4. Route GET /<resource> through pay_kit.try_payment.
--
-- All diagnostics go to stderr; stdout is reserved for the handshake.

package.path = table.concat({
  './?.lua',
  './?/init.lua',
  './lua/?.lua',
  './lua/?/init.lua',
  package.path,
}, ';')

local socket = require('socket')
local cjson  = require('cjson.safe')
local pay_kit = require('pay_kit')
local signer  = require('pay_kit.signer')

local function log(msg)
  io.stderr:write('lua-server: ' .. msg .. '\n')
  io.stderr:flush()
end

local function require_env(name)
  local v = os.getenv(name)
  if v == nil or v == '' then log('missing required env: ' .. name); os.exit(2) end
  return v
end

local function optional_env(name, default)
  local v = os.getenv(name)
  if v == nil or v == '' then return default end
  return v
end

-- --- detect intent --------------------------------------------------

local explicit = (os.getenv('PAY_KIT_INTEROP_PROTOCOL') or ''):lower()
local x402_active
if explicit == 'x402' then
  x402_active = true
elseif explicit == 'mpp' or explicit == 'charge' then
  x402_active = false
else
  x402_active = (os.getenv('X402_INTEROP_RPC_URL') or '') ~= ''
  local mpp_active = (os.getenv('MPP_INTEROP_RPC_URL') or '') ~= ''
  if x402_active == mpp_active then
    log('set exactly one of X402_INTEROP_RPC_URL / MPP_INTEROP_RPC_URL, or set PAY_KIT_INTEROP_PROTOCOL')
    os.exit(2)
  end
end

local protocol = x402_active and 'x402' or 'mpp'

-- --- per-protocol env read -----------------------------------------

local rpc_url, pay_to, amount_units, mint, resource_path, network_raw
local facilitator_secret_json, mpp_secret, settlement_header, mpp_fee_payer_json

if x402_active then
  rpc_url       = require_env('X402_INTEROP_RPC_URL')
  pay_to        = require_env('X402_INTEROP_PAY_TO')
  facilitator_secret_json = require_env('X402_INTEROP_FACILITATOR_SECRET_KEY')
  amount_units  = optional_env('X402_INTEROP_AMOUNT', '1000')
  mint          = optional_env('X402_INTEROP_MINT', 'USDC')
  network_raw   = optional_env('X402_INTEROP_NETWORK', 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1')
  resource_path = optional_env('X402_INTEROP_RESOURCE_PATH', '/paid')
  settlement_header = optional_env('X402_INTEROP_SETTLEMENT_HEADER',
                                   'x-payment-settlement-signature')
else
  rpc_url       = require_env('MPP_INTEROP_RPC_URL')
  pay_to        = require_env('MPP_INTEROP_PAY_TO')
  mint          = require_env('MPP_INTEROP_MINT')
  amount_units  = require_env('MPP_INTEROP_AMOUNT')
  mpp_secret    = optional_env('MPP_INTEROP_SECRET_KEY', 'pay-kit-interop-secret')
  network_raw   = optional_env('MPP_INTEROP_NETWORK', 'localnet')
  resource_path = optional_env('MPP_INTEROP_RESOURCE_PATH', '/paid')
  settlement_header = optional_env('MPP_INTEROP_SETTLEMENT_HEADER',
                                   'x-payment-settlement-signature')
  mpp_fee_payer_json = optional_env('MPP_INTEROP_FEE_PAYER_SECRET_KEY', nil)
end

local splits_raw = optional_env('MPP_INTEROP_SPLITS', '[]')
local splits_decoded = (function()
  local ok, parsed = pcall(cjson.decode, splits_raw)
  if not ok or type(parsed) ~= 'table' then return {} end
  return parsed
end)()

-- --- map network ---------------------------------------------------

local function map_network(raw)
  if raw:find('^solana:') then
    if raw == 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' then return 'solana_mainnet' end
    return 'solana_devnet'  -- devnet + surfpool share devnet CAIP-2 mapping
  end
  if raw == 'mainnet' then return 'solana_mainnet' end
  if raw == 'devnet'  then return 'solana_devnet'  end
  return 'solana_localnet'
end

-- --- amount: convert smallest-units integer to decimal string ------

local function units_to_decimal(units_str, decimals)
  decimals = decimals or 6
  local n = tonumber(units_str)
  if not n then return '0' end
  local divisor = 10 ^ decimals
  local whole = math.floor(n / divisor)
  local frac = n - (whole * divisor)
  if frac == 0 then return tostring(whole) end
  local s = string.format('%d.%0' .. decimals .. 'd', whole, frac)
  return (s:gsub('0+$', ''))
end

-- --- configure -----------------------------------------------------

local network_sym = map_network(network_raw)

local operator_signer
local operator_fee_payer = x402_active
if x402_active then
  local sgn, err = signer.json(facilitator_secret_json)
  if not sgn then log('signer.json: ' .. tostring(err)); os.exit(2) end
  operator_signer = sgn
elseif mpp_fee_payer_json then
  -- MPP scenarios pass the surfpool fee-payer keypair via env. Use
  -- it as the operator's signer so the inner mpp.server's pull
  -- cosign path has a key to sign with.
  local sgn, err = signer.json(mpp_fee_payer_json)
  if not sgn then log('mpp fee_payer signer.json: ' .. tostring(err)); os.exit(2) end
  operator_signer = sgn
  operator_fee_payer = true
end

local ok, cfg_err = pay_kit.configure({
  network     = network_sym,
  accept      = {protocol},
  rpc_url     = rpc_url,
  stablecoins = {mint},
  operator = {
    recipient = pay_to,
    signer    = operator_signer,
    fee_payer = operator_fee_payer,
  },
  mpp = {
    realm                    = 'PayKit Interop',
    challenge_binding_secret = mpp_secret,
  },
})
if not ok then log('configure: ' .. tostring(cfg_err)); os.exit(2) end

local amount_decimal = units_to_decimal(amount_units, 6)
local gate_opts = {amount = assert(pay_kit.usd(amount_decimal, mint))}
assert(pay_kit.gate('paid', gate_opts))

if #splits_decoded > 0 then
  local override = {}
  for _, s in ipairs(splits_decoded) do
    local entry = {recipient = s.recipient, amount = tostring(s.amount)}
    if s.ataCreationRequired == true then entry.ataCreationRequired = true end
    if s.memo then entry.memo = s.memo end
    override[#override + 1] = entry
  end
  require('pay_kit.protocols.mpp').set_splits_override('paid', override)
end

-- --- HTTP loop -----------------------------------------------------

local function send_response(client, status, hdrs, body)
  local reason = ({[200]='OK',[402]='Payment Required',[404]='Not Found',[500]='Server Error'})[status]
    or 'Server Error'
  local payload = type(body) == 'string' and body or cjson.encode(body)
  local merged = {connection = 'close', ['content-length'] = tostring(#payload)}
  for k, v in pairs(hdrs or {}) do merged[k] = v end
  client:send('HTTP/1.1 ' .. status .. ' ' .. reason .. '\r\n')
  for k, v in pairs(merged) do client:send(k .. ': ' .. v .. '\r\n') end
  client:send('\r\n' .. payload)
end

local function read_request(client)
  local request_line = client:receive('*l')
  if not request_line then return nil end
  local method, path = request_line:match('^(%S+)%s+(%S+)')
  if not method then return nil end
  local req_headers = {}
  while true do
    local line = client:receive('*l')
    if not line or line == '' then break end
    local name, value = line:match('^([^:]+):%s*(.+)$')
    if name then req_headers[name:lower()] = value end
  end
  return {method = method, path = path, headers = req_headers}
end

local listener, bind_err = socket.bind('127.0.0.1', 0)
if not listener then log('bind: ' .. tostring(bind_err)); os.exit(2) end
local _, port = listener:getsockname()

io.stdout:write(cjson.encode({
  type = 'ready',
  implementation = 'lua',
  role = 'server',
  port = port,
  capabilities = {x402_active and 'exact' or 'charge'},
}) .. '\n')
io.stdout:flush()

while true do
  local client = listener:accept()
  if not client then break end
  client:settimeout(10)
  local req = read_request(client)
  if not req then
    client:close()
  elseif req.method == 'GET' and req.path == '/health' then
    send_response(client, 200, {['content-type'] = 'application/json'}, {ok = true})
    client:close()
  elseif req.method == 'GET' and req.path == resource_path then
    local payment, perr, response = pay_kit.try_payment('paid', {
      method  = req.method,
      path    = req.path,
      headers = req.headers,
      query   = {},
    })
    if payment then
      local resp_headers = {['content-type'] = 'application/json'}
      for k, v in pairs(payment.settlement_headers or {}) do
        resp_headers[k] = v
      end
      if settlement_header ~= 'x-payment-settlement-signature' and payment.transaction then
        resp_headers[settlement_header] = payment.transaction
      end
      send_response(client, 200, resp_headers, {
        ok = true,
        paid = true,
        protocol = payment.protocol,
        transaction = payment.transaction,
      })
    else
      local resp_headers = {['content-type'] = 'application/json'}
      local body = {error = perr or 'payment_required'}
      if response then
        body = response.body
        for k, v in pairs(response.headers or {}) do resp_headers[k] = v end
      end
      -- Map canonical pay_kit error strings to the cross-SDK `code`
      -- field the harness asserts against (G39).
      if type(perr) == 'string' then
        if perr:find('wrong network', 1, true) then
          body.code = 'wrong_network'
        elseif perr:find('charge_request_mismatch', 1, true) or
               perr:find('does not match server challenge', 1, true) then
          body.code = 'charge_request_mismatch'
        elseif perr:find('signature_consumed', 1, true) or
               perr:find('signature consumed', 1, true) then
          body.code = 'signature_consumed'
        elseif perr:find('invalid proof', 1, true) then
          body.code = 'invalid_proof'
        end
      end
      send_response(client, 402, resp_headers, body)
    end
    client:close()
  else
    send_response(client, 404, {['content-type'] = 'application/json'}, {error = 'not_found'})
    client:close()
  end
end
