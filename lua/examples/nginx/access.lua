-- Access-phase MPP middleware for OpenResty / Kong.
--
-- Issues a signed `WWW-Authenticate: Payment ...` challenge on a
-- missing or invalid credential and lets the upstream content phase
-- render the protected payload only on a successful settlement.
--
-- The Solana stack required for on-chain settlement (base58 +
-- transaction bincode codec + Ed25519 signer + ATA derive) ships in
-- the follow-up Lua PR B; this file uses a stub `verify_payment`
-- that always rejects so the example demonstrates challenge issuance
-- without claiming settlement support PR A does not own. Once PR B
-- lands, swap the stub for `mpp.server.solana_verify.new_signature_verifier`
-- and `pay curl http://127.0.0.1:4570/paid` returns 200.

local mpp = require('mpp')
local json = require('mpp.util.json')
local headers = require('mpp.protocol.core.headers')

local function env(name, default)
  local value = os.getenv(name)
  if value == nil or value == '' then return default end
  return value
end

-- PR B replaces this stub with the real Solana verifier.
local function stub_verify_payment(_context)
  error({
    code = 'settlement-deferred',
    message = 'settlement requires the Solana stack landing in PR B',
  })
end

local server = mpp.server.new({
  recipient = env('MPP_PAY_TO', 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
  currency = env('MPP_CURRENCY', 'USDC'),
  decimals = 6,
  network = env('MPP_NETWORK', 'localnet'),
  secret_key = env('MPP_SECRET_KEY', 'lua-mpp-dev-secret'),
  realm = 'Lua MPP Example (nginx)',
  verify_payment = stub_verify_payment,
})

local AMOUNT = env('MPP_AMOUNT', '1000')

local function respond(status, hdrs, body)
  ngx.status = status
  for name, value in pairs(hdrs or {}) do
    ngx.header[name] = value
  end
  ngx.say(body)
  return ngx.exit(status)
end

local function payment_required()
  local challenge = server:charge(AMOUNT)
  respond(402, {
    ['content-type'] = 'application/json',
    ['www-authenticate'] = headers.format_www_authenticate(challenge),
  }, json.encode({ error = 'payment required' }))
end

local function attempt_settlement(authorization)
  local ok, settlement = pcall(function()
    return server:verify_credential_with_expected(authorization, {
      amount = AMOUNT,
      currency = server.currency,
      recipient = server.recipient,
    })
  end)
  if ok then
    local hdrs = {}
    if settlement and settlement.headers then
      for name, value in pairs(settlement.headers) do
        hdrs[name] = value
      end
    end
    -- 200 falls through to the upstream content phase; just set headers.
    for name, value in pairs(hdrs) do
      ngx.header[name] = value
    end
    return
  end
  local detail = type(settlement) == 'table'
    and settlement.message or tostring(settlement)
  respond(402, { ['content-type'] = 'application/json' },
    json.encode({ error = 'verification failed', detail = detail }))
end

local auth = ngx.var.http_authorization
if not auth or auth == '' then
  payment_required()
else
  attempt_settlement(auth)
end
