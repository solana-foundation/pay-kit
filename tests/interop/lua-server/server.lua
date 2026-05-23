#!/usr/bin/env luajit
-- Lua MPP interop adapter for the cross-language harness.
--
-- Mirrors `tests/interop/ruby-server/server.rb`: a raw TCP loop that
-- gates `interopScenario.resourcePath` behind a `charge` challenge and
-- settles the credential on Surfpool. The harness drives this binary by
-- the contract in `skills/pay-sdk-implementation/references/interop-harness.md`:
--
--   1. Set environment variables (MPP_INTEROP_*).
--   2. Spawn the adapter.
--   3. Read one JSON line from stdout: {"type":"ready", ...}.
--   4. Drive the resource over HTTP on the port the adapter reports.
--   5. Send SIGTERM to shut down.
--
-- All diagnostic logs go to stderr; stdout is reserved for the handshake.
--
-- Run manually:
--   cd lua && eval "$(luarocks --lua-version=5.1 --tree lua_modules path)"
--   MPP_INTEROP_RPC_URL=... MPP_INTEROP_PAY_TO=... ... luajit ../tests/interop/lua-server/server.lua

package.path = table.concat({
  './?.lua',
  './?/init.lua',
  './lua/?.lua',
  './lua/?/init.lua',
  package.path,
}, ';')

local socket = require('socket')
local mpp = require('mpp')
local json = require('mpp.util.json')
local headers = require('mpp.protocol.core.headers')
local solana_verify = require('mpp.server.solana_verify')
local charge_handler = require('mpp.server.charge_handler')
local rpc_module = require('mpp.solana.rpc')
local rpc_transport = require('mpp.solana.rpc_transport')
local error_codes = require('mpp.protocol.core.error_codes')
local signer_module = require('mpp.methods.solana.signer')
local store_module = require('mpp.store')

local function log(message)
  io.stderr:write(message .. '\n')
  io.stderr:flush()
end

local function require_env(name)
  local value = os.getenv(name)
  if value == nil or value == '' then
    log('missing required env: ' .. name)
    os.exit(2)
  end
  return value
end

local function optional_env(name, default)
  local value = os.getenv(name)
  if value == nil or value == '' then
    return default
  end
  return value
end

local rpc_url           = require_env('MPP_INTEROP_RPC_URL')
local network           = optional_env('MPP_INTEROP_NETWORK', 'localnet')
local mint              = require_env('MPP_INTEROP_MINT')
local amount            = require_env('MPP_INTEROP_AMOUNT')
local pay_to            = require_env('MPP_INTEROP_PAY_TO')
-- The HMAC secret gates challenge-signature validity, so an attacker who
-- knows the default literal could craft a syntactically valid Payment
-- credential off-line. The interop fixture insists on an explicit value
-- and fails fast at boot if it is missing.
local secret_key        = require_env('MPP_INTEROP_SECRET_KEY')
local resource_path     = optional_env('MPP_INTEROP_RESOURCE_PATH', '/paid')
local settlement_header = optional_env('MPP_INTEROP_SETTLEMENT_HEADER', 'x-payment-settlement-signature')
local replay_path       = os.getenv('MPP_INTEROP_REPLAY_SOURCE_PATH')
local replay_amount     = os.getenv('MPP_INTEROP_REPLAY_SOURCE_AMOUNT')
local splits_raw        = optional_env('MPP_INTEROP_SPLITS', '[]')

-- Scenario-configurable decimals. Defaults to 6 (the SPL stablecoin
-- baseline). The harness drives the value through `MPP_INTEROP_DECIMALS`
-- for scenarios that deploy mints under a different decimal count
-- (e.g. the 9-decimal native mints under G07). Adapters that ignore this
-- env emit transferChecked instructions whose `data[9]` byte mismatches
-- the deploy-time mint state and the harness rejects the settlement.
local decimals          = tonumber(optional_env('MPP_INTEROP_DECIMALS', '6'))
if decimals == nil or decimals < 0 or decimals > 18 or decimals % 1 ~= 0 then
  log('MPP_INTEROP_DECIMALS must be an integer 0..18, got ' .. tostring(os.getenv('MPP_INTEROP_DECIMALS')))
  os.exit(2)
end

-- Optional token program override. The harness sets this for Token-2022
-- scenarios where the SDK's built-in symbol table cannot disambiguate the
-- mint (e.g. arbitrary mints deployed in tests). When unset the server
-- falls back to the SDK's per-currency default which uses the stablecoin
-- table in `mpp.protocol.solana`.
local token_program     = os.getenv('MPP_INTEROP_TOKEN_PROGRAM')
if token_program == '' then token_program = nil end

local splits_decoded, splits_err = json.decode(splits_raw)
if type(splits_decoded) ~= 'table' then
  log('MPP_INTEROP_SPLITS must decode to an array: ' .. tostring(splits_err))
  os.exit(2)
end

local fee_payer = signer_module.from_json_array(require_env('MPP_INTEROP_FEE_PAYER_SECRET_KEY'))

local rpc = rpc_module.new({ url = rpc_url, transport = rpc_transport.new() })
local verifier_bundle = solana_verify.new_real_verifier({ pull_signer = fee_payer })

local handler = charge_handler.new({
  rpc = rpc,
  network = network,
  replay_store = store_module.memory(),
  transaction_verifier = verifier_bundle.transaction_verifier,
  pull_transaction_signer = verifier_bundle.pull_transaction_signer,
  pull_blockhash_extractor = verifier_bundle.pull_blockhash_extractor,
})

local server = mpp.server.new({
  recipient = pay_to,
  currency = mint,
  decimals = decimals,
  network = network,
  rpc_url = rpc_url,
  secret_key = secret_key,
  realm = 'MPP Interop',
  fee_payer = true,
  fee_payer_key = fee_payer.public_key,
  verify_payment = handler:as_callback(),
})

local function read_request(conn)
  local line = conn:receive('*l')
  if not line or line == '' then return nil end
  local method, path = line:match('^(%S+)%s+(%S+)%s+HTTP/')
  if not method then return nil end
  local hdrs = {}
  while true do
    local h = conn:receive('*l')
    if not h or h == '' then break end
    local name, value = h:match('^([^:]+):%s*(.*)$')
    if name then hdrs[name:lower()] = value end
  end
  return { method = method, path = path, headers = hdrs }
end

local STATUS_REASONS = {
  [200] = 'OK',
  [402] = 'Payment Required',
  [404] = 'Not Found',
  [500] = 'Server Error',
}

-- conn:send returns nil + error string on broken pipe / closed peer rather
-- than raising, but a subsequent send on the same closed socket short-cuts
-- straight back. Bail out of the response write on the first failure so
-- we do not log spurious failures for every line in the response, and so
-- the surrounding pcall in serve_one observes the partial write cleanly.
local function safe_send(conn, chunk)
  local ok, sent_or_err = pcall(conn.send, conn, chunk)
  if not ok then
    return nil, tostring(sent_or_err)
  end
  if sent_or_err == nil then
    return nil, 'send returned nil'
  end
  return true
end

local function write_response(conn, status, hdrs, body)
  local reason = STATUS_REASONS[status] or 'Server Error'
  local payload
  if type(body) == 'string' then
    payload = body
  else
    payload = json.encode(body)
  end
  hdrs = hdrs or {}
  hdrs['connection'] = 'close'
  hdrs['content-length'] = tostring(#payload)
  local lines = { 'HTTP/1.1 ' .. status .. ' ' .. reason .. '\r\n' }
  for name, value in pairs(hdrs) do
    lines[#lines + 1] = name .. ': ' .. value .. '\r\n'
  end
  lines[#lines + 1] = '\r\n'
  lines[#lines + 1] = payload
  for i = 1, #lines do
    local ok, err = safe_send(conn, lines[i])
    if not ok then
      log('response write aborted: ' .. tostring(err))
      return
    end
  end
end

-- Convert a base-unit amount (the harness env-var format) into the display
-- string the SDK's parse_units expects. The harness sends raw u64 base units
-- but Server:charge_with_options runs parse_units(amount, decimals); without
-- a conversion the displayed amount would be multiplied by 10^decimals twice.
local function base_units_to_display(value, dec)
  if dec == 0 then
    return value
  end
  local s = tostring(value)
  if #s <= dec then
    s = string.rep('0', dec - #s + 1) .. s
  end
  local whole = s:sub(1, #s - dec)
  local fractional = s:sub(#s - dec + 1)
  fractional = fractional:gsub('0+$', '')
  if fractional == '' then
    return whole
  end
  return whole .. '.' .. fractional
end

local function build_charge_options(request_amount)
  local options = {
    description = 'Lua interop protected content',
  }
  if #splits_decoded > 0 then
    options.splits = splits_decoded
  end
  if token_program then
    options.token_program = token_program
  end
  return base_units_to_display(request_amount, decimals), options
end

local function handle_charge(conn, authorization, expected_amount)
  if authorization == nil or authorization == '' then
    -- Issue a fresh signed challenge.
    local display_amount, charge_options = build_charge_options(expected_amount)
    local ok, challenge_value = pcall(function()
      return server:charge_with_options(display_amount, charge_options)
    end)
    if not ok then
      -- Pre-issuance rejections (e.g. Tier-0 splits guard, malformed
      -- amount) raise the same canonical {code, message} table the
      -- verifier raises later. Surface them as a 402 with the structured
      -- code rather than a 500 so the harness's status assertion holds
      -- and the cross-SDK fault matrix sees the same `payment_invalid`
      -- code every other server emits. Bare-string errors fall through
      -- to `error_codes.to_response` which tags them with
      -- `challenge_verification_failed` per the helper's contract.
      local response = error_codes.to_response(challenge_value)
      log('charge issuance error: ' .. tostring(response.message) .. ' (' .. tostring(response.code) .. ')')
      write_response(conn, 402, { ['content-type'] = 'application/json' }, response)
      return
    end
    write_response(conn, 402, {
      ['content-type'] = 'application/json',
      ['www-authenticate'] = headers.format_www_authenticate(challenge_value),
    }, {
      error = 'payment required',
      message = 'payment required',
      code = error_codes.CHALLENGE_VERIFICATION_FAILED,
    })
    return
  end

  -- Parse the Authorization header into a credential structure.
  local credential, parse_err = headers.parse_authorization(authorization)
  if not credential then
    log('authorization parse error: ' .. tostring(parse_err))
    write_response(conn, 402, { ['content-type'] = 'application/json' }, {
      error = 'invalid authorization',
      message = tostring(parse_err or 'invalid authorization'),
      code = error_codes.CHALLENGE_VERIFICATION_FAILED,
    })
    return
  end

  -- The credential carries the amount in base units (already parsed by the
  -- challenge issuance pipeline), so the expected-amount comparison must
  -- also be in base units (not the display form the harness env var uses).
  local ok, settlement = pcall(function()
    return server:verify_credential_with_expected(credential, {
      amount = expected_amount,
      currency = mint,
      recipient = pay_to,
    })
  end)
  if not ok then
    local response = error_codes.to_response(settlement)
    log('settlement error: ' .. tostring(response.message) .. ' (' .. tostring(response.code) .. ')')
    write_response(conn, 402, { ['content-type'] = 'application/json' }, response)
    return
  end

  -- The receipt structure carries the settlement reference (on-chain signature).
  local response_headers = { ['content-type'] = 'application/json' }
  if settlement and settlement.headers then
    for name, value in pairs(settlement.headers) do
      response_headers[name] = value
    end
  end
  -- The harness asserts the configured settlement header is present on the
  -- success path. The Lua receipt object exposes the on-chain signature as
  -- `reference`; surface it under the harness header.
  if settlement and settlement.reference then
    response_headers[settlement_header] = settlement.reference
  end
  write_response(conn, 200, response_headers, { ok = true, paid = true })
end

local listener = assert(socket.bind('127.0.0.1', 0))
listener:settimeout(0.2)
local _, port = listener:getsockname()
port = tonumber(port)

io.stdout:write(json.encode({
  type = 'ready',
  implementation = 'lua',
  role = 'server',
  port = port,
  capabilities = { 'charge' },
}) .. '\n')
io.stdout:flush()

log('lua interop server listening on 127.0.0.1:' .. tostring(port)
  .. ' rpc_url=' .. tostring(rpc_url)
  .. ' network=' .. tostring(network)
  .. ' mint=' .. tostring(mint)
  .. ' pay_to=' .. tostring(pay_to)
  .. ' fee_payer=' .. tostring(fee_payer.public_key))

local function serve_one()
  local conn = listener:accept()
  if not conn then return end
  conn:settimeout(5)
  local req = read_request(conn)
  if not req then
    conn:close()
    return
  end
  if req.method == 'GET' and req.path == '/health' then
    write_response(conn, 200, { ['content-type'] = 'application/json' }, { ok = true })
    conn:close()
    return
  end
  local protected_amount
  if req.method == 'GET' and req.path == resource_path then
    protected_amount = amount
  elseif req.method == 'GET' and replay_path and req.path == replay_path then
    protected_amount = replay_amount or amount
  end
  if protected_amount == nil then
    write_response(conn, 404, { ['content-type'] = 'application/json' }, { error = 'not_found' })
    conn:close()
    return
  end
  handle_charge(conn, req.headers['authorization'], protected_amount)
  conn:close()
end

-- Avoid a 100 % CPU spin between accept timeouts. The 0.2 s accept
-- timeout pairs with a tiny socket.select sleep so the lua interop server
-- yields when idle, which matters when multiple language adapters are
-- spawned back-to-back by the matrix harness on the same host. Without
-- the yield the OS scheduler can starve neighbouring adapters during
-- their startup window and surface as `connect ECONNREFUSED` on what
-- looks like a freshly-bound socket.
while true do
  local ok, err = pcall(serve_one)
  if not ok then
    log('serve error: ' .. tostring(err))
  end
  socket.select(nil, nil, 0.005)
end
