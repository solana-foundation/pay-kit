-- Lua cross-SDK conformance-vector runner.
--
-- Honors the same stdin/stdout contract as the TypeScript reference runner
-- (harness/src/conformance/ts-runner.ts) and the Go runner
-- (go/cmd/conformance/main.go): read one conformance vector as JSON on
-- stdin, drive the real Lua pay_kit SDK for the requested mode, and emit
-- one RunnerResult line as JSON on stdout.
--
-- ROLE: the Lua SDK is SERVER-ONLY. It ships a pre-broadcast charge
-- verifier (pay_kit.solana.verifier), the x402 exact server adapter
-- (pay_kit.protocols.x402) and the wire canonical-JSON / base64url
-- encoders, but no client-side transaction builder. The runner therefore
-- supports:
--   * canonical-bytes     -- JCS (RFC 8785) + base64url + challenge id
--   * verify-transaction  -- the charge verifier over the vector's pinned
--     transaction, request passed verbatim
--   * x402 verify         -- Adapter:verify_payment, the SDK's pre-broadcast
--     verification, against a PayKit config built from the vector route and
--     the fixture RPC at input.rpcUrl
-- Build vectors, and verify vectors that pin no transaction (they need a
-- client build first), emit "unsupported-mode" so the driver SKIPs them.
-- The runner fills no defaults, resolves no token programs or decimals and
-- applies no field precedence (harness/expectations/RULINGS.md).
--
-- Run from the `lua/` directory so the `./?.lua` / `./?/init.lua` package
-- path resolves the pay_kit tree, and `./lua_modules` (the luarocks tree CI
-- installs) resolves cjson and luasocket for the x402 adapter.

package.path = table.concat({
  './?.lua',
  './?/init.lua',
  './lua_modules/share/lua/5.1/?.lua',
  './lua_modules/share/lua/5.1/?/init.lua',
  package.path,
}, ';')
package.cpath = './lua_modules/lib/lua/5.1/?.so;' .. package.cpath

local json = require('pay_kit.util.json')
local base64url = require('pay_kit.util.base64url')
local base64_std = require('pay_kit.util.base64_std')
local challenge = require('pay_kit.protocol.core.challenge')
local verifier = require('pay_kit.solana.verifier')
local transaction = require('pay_kit.solana.transaction')
local instructions = require('pay_kit.solana.instructions')

local UNSUPPORTED_MODE = 'unsupported-mode'

local TOKEN_PROGRAM = instructions.TOKEN_PROGRAM
local TOKEN_2022_PROGRAM = instructions.TOKEN_2022_PROGRAM
local SYSTEM_PROGRAM = instructions.SYSTEM_PROGRAM
local MEMO_PROGRAM = instructions.MEMO_PROGRAM
local COMPUTE_BUDGET_PROGRAM = instructions.COMPUTE_BUDGET_PROGRAM

-- Read all of stdin into one string.
local function read_stdin()
  return io.read('*a') or ''
end

-- Decode a lower/upper hex string into a raw byte string.
local function hex_to_bytes(hex)
  if #hex % 2 ~= 0 then
    error('hex string must have an even length')
  end
  local out = {}
  for i = 1, #hex, 2 do
    local byte = tonumber(hex:sub(i, i + 1), 16)
    if byte == nil then
      error('invalid hex byte at offset ' .. i)
    end
    out[#out + 1] = string.char(byte)
  end
  return table.concat(out)
end

-- Emit one RunnerResult line. The JSON encoder is the SDK's RFC 8785 JCS
-- encoder; key order is canonical, which is fine because the driver parses
-- the line with JSON.parse and reads fields by name.
local function emit(result)
  io.write(json.encode(result) .. '\n')
end
-- Decode a base64 wire transaction into the semantic shape the conformance
-- driver asserts against. Mirrors the TS reference decoder
-- (harness/src/conformance/decode.ts) and the Go shapeFromTransaction:
-- fee payer is account[0], SPL transfers come from transferChecked
-- (discriminator 12), SOL transfers from the System Program transfer
-- (discriminator 2), memos from the Memo Program, and compute caps from
-- the ComputeBudget program.
local function shape_from_transaction(transaction_base64)
  local tx = transaction.from_base64(transaction_base64)
  local keys = tx.message.account_keys
  if #keys == 0 then
    error('transaction has no account keys')
  end

  local shape = {
    feePayer = keys[1],
    forbiddenPrograms = {},
    transfers = {},
    memo = {},
  }

  for _, ix in ipairs(tx.message.instructions) do
    local program = instructions.program_id_for(tx, ix)
    local data = ix.data

    if program == COMPUTE_BUDGET_PROGRAM then
      if #data == 5 and data:byte(1) == 2 then
        shape.maxComputeUnitLimit = tonumber(instructions.decode_le_uint(data, 2, 4))
      elseif #data == 9 and data:byte(1) == 3 then
        shape.maxComputeUnitPrice = instructions.decode_le_uint(data, 2, 8)
      end
    elseif program == MEMO_PROGRAM then
      shape.memo[#shape.memo + 1] = data
    elseif program == SYSTEM_PROGRAM then
      local parsed = instructions.parse_system_transfer(ix)
      if parsed then
        local dest = tx.message.account_keys[ix.accounts[2] + 1]
        shape.transfers[#shape.transfers + 1] = {
          kind = 'sol',
          destination = dest,
          amount = parsed.lamports,
        }
      end
    elseif program == TOKEN_PROGRAM or program == TOKEN_2022_PROGRAM then
      local parsed = instructions.parse_transfer_checked(ix)
      if parsed then
        local mint = tx.message.account_keys[ix.accounts[2] + 1]
        local dest = tx.message.account_keys[ix.accounts[3] + 1]
        shape.transfers[#shape.transfers + 1] = {
          kind = 'spl',
          destination = dest,
          mint = mint,
          amount = parsed.amount,
          decimals = parsed.decimals,
          tokenProgram = program,
        }
      end
    end
  end

  return shape
end

local function run_canonical_bytes(vector)
  local input = vector.input or {}
  local exact = {}
  if input.value ~= nil then
    local canonical = json.encode(input.value)
    exact.canonicalJson = canonical
    exact.base64Url = base64url.encode(canonical)
  end
  if type(input.encodeBase64Url) == 'table' then
    local enc = input.encodeBase64Url
    if type(enc.hexBytes) == 'string' and enc.hexBytes ~= '' then
      local raw = hex_to_bytes(enc.hexBytes)
      local bytes = {}
      for i = 1, #raw do
        bytes[i] = raw:byte(i)
      end
      -- Preserve an empty-table-as-array marker is unnecessary here because
      -- the 48-byte vector is always non-empty; the driver compares the
      -- numeric array element-wise.
      exact.bytes = bytes
      exact.base64Url = base64url.encode(raw)
    elseif type(enc.utf8) == 'string' then
      exact.base64Url = base64url.encode(enc.utf8)
    end
  end
  if type(input.challengeId) == 'table' then
    -- base64url(HMAC-SHA256(secret, realm|method|intent|request|expires|
    -- digest|opaque)); absent optionals join as empty strings. Drives the
    -- production SDK derivation (challenge.compute_challenge_id), mirroring
    -- rust compute_challenge_id (protocol/core/challenge.rs).
    local cid = input.challengeId
    exact.base64Url = challenge.compute_challenge_id(
      cid.secretKey,
      cid.realm,
      cid.method,
      cid.intent,
      cid.request,
      cid.expires,
      cid.digest,
      cid.opaque
    )
  end
  return { id = vector.id, outcome = 'accept', exactBytes = exact }
end

-- build-transaction: no server-only equivalent. The Lua SDK ships no
-- client builder, so report unsupported-mode and let the driver SKIP.
local function run_build_transaction(vector)
  return {
    id = vector.id,
    outcome = UNSUPPORTED_MODE,
    error = 'lua SDK is server-only: no client-side transaction builder',
  }
end

-- verify-transaction (charge): run the SDK's pre-broadcast verifier over the
-- vector's pinned transaction, with the request passed verbatim. A vector
-- that pins no transaction needs a client build first; the runner never
-- fabricates one.
local function run_verify_transaction(vector)
  local input = vector.input or {}
  if type(input.request) ~= 'table' then
    error('verify vector is missing input.request')
  end
  local tx = input.transaction
  if type(tx) ~= 'string' or tx == '' then
    return {
      id = vector.id,
      outcome = UNSUPPORTED_MODE,
      error = 'lua SDK is server-only: this verify vector pins no transaction, '
        .. 'so it needs a client build first and lua has no client builder',
    }
  end
  verifier.verify_transaction_base64(tx, input.request)
  return {
    id = vector.id,
    outcome = 'accept',
    transactionShape = shape_from_transaction(tx),
  }
end

-- ── x402 `exact` ──
--
-- verify-transaction (x402): configure PayKit for the vector's route the way
-- an operator would (network, recipient, fee payer, rpc_url = the fixture RPC,
-- payment-identifier requirement) and run the SDK's pre-broadcast verifier
-- (Adapter:verify_payment: version gate, offer binding, extensions gate,
-- structural transaction verifier, client signatures). Nothing is signed or
-- broadcast. The SDK prices in a gate (a human amount of a settlement coin)
-- and the adapter scales it by the coin's decimals (the built-in table for
-- known coins), so the route's atomic amount maps back with the same table.

local PAYMENT_IDENTIFIER_KEY = 'payment-identifier'
local decode_envelope_shape

local function pay_kit_network(slug)
  if slug == 'mainnet' or slug == 'mainnet-beta' or slug == 'solana' then
    return 'solana_mainnet'
  elseif slug == 'localnet' then
    return 'solana_localnet'
  end
  return 'solana_devnet'
end

-- "1000" atomic units of a 6-decimal coin -> "0.001".
local function units_to_decimal(units, decimals)
  if type(units) ~= 'string' or not units:match('^%d+$') then
    error('x402ServerAmount must be an atomic-unit integer string')
  end
  local padded = string.rep('0', math.max(0, decimals + 1 - #units)) .. units
  local whole = padded:sub(1, #padded - decimals)
  local fraction = (decimals > 0 and padded:sub(-decimals) or ''):gsub('0+$', '')
  if fraction == '' then return whole end
  return whole .. '.' .. fraction
end

local function run_x402_verify(vector)
  local input = vector.input or {}
  local header = input.x402PaymentHeader
  if type(header) ~= 'string' or header == '' then
    error('invalid payload: x402 verify vector missing input.x402PaymentHeader')
  end
  for _, key in ipairs({'x402ServerNetwork', 'x402ServerRecipient', 'x402ServerCurrency',
                        'x402ServerAmount', 'x402ServerFeePayerSecretKey', 'rpcUrl'}) do
    if input[key] == nil then
      error('x402 verify vector missing input.' .. key)
    end
  end

  -- The PayKit x402 adapter pulls in cjson and the RPC transport, so it is
  -- only loaded on this path.
  local pay_kit = require('pay_kit')
  local signer = require('pay_kit.signer')
  local x402 = require('pay_kit.protocols.x402')

  local sgn = assert(signer.bytes(input.x402ServerFeePayerSecretKey))
  local ok, err = pay_kit.configure({
    network     = pay_kit_network(input.x402ServerNetwork),
    accept      = {'x402'},
    rpc_url     = input.rpcUrl,
    stablecoins = {input.x402ServerCurrency},
    operator    = {recipient = input.x402ServerRecipient, signer = sgn, fee_payer = true},
    x402        = {requires_payment_identifier = input.x402ServerRequiresPaymentIdentifier == true},
    -- No boot-time preflight (fee-payer balance / ATA provisioning) and no
    -- generated MPP secret persisted to ./.env: this is a verify-only run.
    preflight   = false,
    mpp         = {challenge_binding_secret = 'unused-x402-conformance-secret-0123456789'},
  })
  if not ok then error(err) end
  local decimals = assert(require('pay_kit.solana.mints').decimals_for(input.x402ServerCurrency),
    'x402ServerCurrency is not a known coin')
  assert(pay_kit.gate('route', {
    amount = assert(pay_kit.usd(units_to_decimal(input.x402ServerAmount, decimals), input.x402ServerCurrency)),
  }))
  local gate = assert(require('pay_kit.internal.registry').materialize('route'))

  local adapter = assert(x402.new({config_resolver = pay_kit.config}))
  -- The route's extra.memo is the SDK's resource binding: advertised as
  -- extra.memo and enforced on the transaction.
  local memo = input.x402ServerMemo
  local offer, verify_err = adapter:verify_payment(gate, {headers = {['payment-signature'] = header}}, memo)
  if not offer then error(verify_err) end
  return {
    id = vector.id,
    outcome = 'accept',
    x402EnvelopeShape = decode_envelope_shape(header),
  }
end

-- Decode the base64(JSON) payment header into the conformance envelope
-- shape oracle. Mirrors decodeEnvelopeShape in the TS reference: presence
-- of top-level scheme/network and accepted is part of the contract (v1
-- carries scheme+network and no accepted; v2 carries accepted and no
-- top-level scheme/network). Only keys actually present on the wire are
-- set, so the JSON encoder omits the rest and the driver reads them as
-- absent.
function decode_envelope_shape(header)
  local decoded = base64_std.decode(header)
  if not decoded then
    error('invalid payload: payment-signature base64 decode failed')
  end
  local env = json.decode(decoded)
  if type(env) ~= 'table' then
    error('invalid payload: payment-signature not a JSON object')
  end

  local accepted = env.accepted
  local has_accepted = type(accepted) == 'table'
  local payload = env.payload
  local has_tx = type(payload) == 'table'
    and type(payload.transaction) == 'string'
    and payload.transaction ~= ''

  local shape = {
    x402Version = env.x402Version,
    hasAccepted = has_accepted,
    payloadHasTransaction = has_tx,
  }
  if type(env.scheme) == 'string' then
    shape.scheme = env.scheme
  end
  if type(env.network) == 'string' then
    shape.network = env.network
  end
  if has_accepted then
    if type(accepted.scheme) == 'string' then shape.acceptedScheme = accepted.scheme end
    if type(accepted.network) == 'string' then shape.acceptedNetwork = accepted.network end
    if type(accepted.asset) == 'string' then shape.acceptedAsset = accepted.asset end
    if type(accepted.payTo) == 'string' then shape.acceptedPayTo = accepted.payTo end
    if accepted.amount ~= nil then shape.acceptedAmount = tostring(accepted.amount) end
  end

  -- Surface the v2 extensions object (rust PaymentExtensions; TS reference
  -- decodeEnvelopeShape). `hasExtensions` is false when the key is absent OR
  -- present-but-empty: the echo-and-omit rule means a conforming build never
  -- emits an empty `extensions: {}`, but a decoder must still classify a stray
  -- `{}` as "no extensions". `extensionKeys` is sorted so the driver's
  -- toEqual is order-independent.
  local extensions = env.extensions
  if type(extensions) == 'table' then
    local keys = {}
    for key in pairs(extensions) do
      keys[#keys + 1] = key
    end
    table.sort(keys)
    shape.hasExtensions = #keys > 0
    shape.extensionKeys = keys
    local pid = extensions[PAYMENT_IDENTIFIER_KEY]
    shape.hasPaymentIdentifier = type(pid) == 'table'
    if type(pid) == 'table' and type(pid.info) == 'table' then
      if pid.info.required ~= nil then
        shape.paymentIdentifierRequired = pid.info.required
      end
      if pid.info.id ~= nil then
        shape.paymentIdentifierId = pid.info.id
      end
    end
  else
    -- No extensions object on the wire (the conforming echo-and-omit case).
    -- Pin the absence explicitly so a vector can assert it.
    shape.hasExtensions = false
    shape.hasPaymentIdentifier = false
    shape.extensionKeys = {}
  end
  return shape
end


-- x402-exact dispatch. build vectors have no server-only equivalent
-- (the Lua SDK ships no client builder), so they emit unsupported-mode
-- and the driver SKIPs them. verify vectors exercise the real verifier.
local function run_x402_vector(vector)
  if vector.mode == 'build-transaction' then
    return {
      id = vector.id,
      outcome = UNSUPPORTED_MODE,
      error = 'lua SDK is server-only: no client-side x402 builder',
    }
  end
  return run_x402_verify(vector)
end

local function run_vector(vector)
  if vector.intent == 'x402-exact' then
    return run_x402_vector(vector)
  end
  if vector.mode == 'canonical-bytes' then
    return run_canonical_bytes(vector)
  elseif vector.mode == 'build-transaction' then
    return run_build_transaction(vector)
  elseif vector.mode == 'verify-transaction' then
    return run_verify_transaction(vector)
  end
  return {
    id = vector.id,
    outcome = 'reject',
    error = 'unknown mode ' .. tostring(vector.mode),
  }
end

-- Map the Lua SDK's native reject message onto the shared cross-SDK
-- RejectCode vocabulary the harness asserts per reject vector
-- (see harness/vectors/charge-rejects.json `expect.rejectCode`). The
-- match is done on the lowercased message with plain substring checks
-- (string.find with `plain = true`) so Lua-pattern magic characters in
-- the message are treated literally.
--
-- The Lua SDK is server-only: it processes verify-transaction reject
-- vectors that ship a concrete `transaction`, so the only reject vector
-- it actually classifies today is the transferChecked decimals mismatch
-- (which surfaces as a no-matching-transfer reject). The remaining
-- branches stay in place so the classifier matches the other reject
-- families once a built-transaction path exists.
local function has(msg, needle)
  return string.find(msg, needle, 1, true) ~= nil
end

local function classify_reject(message)
  if type(message) ~= 'string' then
    return nil
  end
  local m = message:lower()

  -- Charge verification policy and client challenge checks (mirrors the
  -- block at the top of harness/src/conformance/reject.ts), plus reject.ts's
  -- /unexpected .* instruction/ for the charge allowlist message.
  if has(m, 'fee payer cannot fund') or has(m, 'fee payer token account cannot fund') then
    return 'fee-payer-is-funds-source'
  end
  if has(m, 'primary amount is zero after splits') or has(m, 'split amounts exceed') then
    return 'splits-exceed-amount'
  end
  if has(m, 'splits exceed maximum') then
    return 'too-many-splits'
  end
  if has(m, 'ata creation owner is not authorized') or has(m, 'unsupported compute budget')
    or has(m, 'unexpected_signer')
    or has(m, 'unexpected program instruction in payment transaction') then
    return 'unexpected-instruction'
  end
  if has(m, 'atacreationrequired requires') or has(m, 'unsupported challenge network')
    or has(m, 'invalid amount') or has(m, 'requires feepayerkey') then
    return 'invalid-challenge'
  end
  if has(m, 'ata creation') or has(m, 'ata payer') or has(m, 'transaction fee payer must be')
    or has(m, 'transaction fee payer mismatch') or has(m, 'memo cannot exceed') then
    return 'invalid-payload'
  end

  -- x402 v2: the credential's `accepted` matches none of the route's
  -- requirements (the SDK's targeted field checks or its offer match).
  if has(m, 'recipient mismatch') or has(m, 'currency mismatch')
    or has(m, 'accepted payment requirement does not match')
    or has(m, 'charge_request_mismatch')
    or m:find('amount mismatch: expected %d+, got %d+') then
    return 'accepted-mismatch'
  end
  if has(m, 'no memo instruction found') or has(m, 'memo_mismatch') or has(m, 'memo_count') then
    return 'invalid-payload'
  end
  if has(m, 'unknown_fourth_instruction') or has(m, 'unknown_fifth_instruction')
    or has(m, 'unknown_sixth_instruction') or has(m, 'unknown_optional_instruction')
    or has(m, 'instructions_length') then
    return 'unexpected-instruction'
  end
  if has(m, 'fee_payer_included_in_instruction_accounts') then
    return 'fee-payer-not-authority'
  end

  -- x402-exact: an envelope carrying an x402Version the server does not
  -- understand (the SDK raises "invalid proof: unsupported x402Version").
  -- Checked before the generic `invalid` fallback so the unknown-version
  -- reject lands on its own category, not invalid-payload.
  if has(m, 'unsupported x402version') or has(m, 'unsupported x402 version') then
    return 'unsupported-version'
  end
  -- x402-exact: the credential's network does not match the server route
  -- (the SDK raises "wrong network: ...", and the TS reference raises
  -- "Network mismatch: ...").
  if has(m, 'wrong network') or has(m, 'network mismatch') then
    return 'wrong-network'
  end
  -- x402-exact extensions: the route required a payment-identifier id but the
  -- credential echoed none / an invalid one (the SDK raises a message carrying
  -- "payment-identifier ... required|missing|invalid"). Checked before the
  -- generic invalid/payload fallback so it lands on its own category. Mirrors
  -- reject.ts /payment.identifier .*(required|missing|invalid)/i.
  if has(m, 'payment-identifier')
    and (has(m, 'required') or has(m, 'missing') or has(m, 'invalid')) then
    return 'payment-identifier-required'
  end

  -- x402 exact structural verifier tokens (invalid_exact_svm_payload_*).
  if has(m, 'compute_price_instruction_too_high') then
    return 'compute-price-over-cap'
  end
  if has(m, 'fee_payer_transferring_funds') or has(m, 'fee_payer_in_instruction_accounts') then
    return 'fee-payer-not-authority'
  end
  if has(m, 'no_transfer_instruction') or has(m, 'recipient_mismatch') or has(m, 'mint_mismatch') then
    return 'no-matching-transfer'
  end
  if has(m, 'compute unit price') and has(m, 'exceed')
    and (has(m, 'cap') or has(m, 'maximum')) then
    return 'compute-price-over-cap'
  end
  if has(m, 'compute unit limit') and has(m, 'exceed') then
    return 'compute-limit-over-cap'
  end
  if has(m, 'fee payer cannot authorize') then
    return 'fee-payer-not-authority'
  end
  -- SOLA1-349: payment legs funded by more than one authority, or a required
  -- signer that is neither the fee payer nor that authority.
  if has(m, 'share one funding authority') then
    return 'mixed-funding-authority'
  end
  if has(m, 'unexpected signer') then
    return 'unexpected-signer'
  end
  if has(m, 'splits consume the entire amount')
    or has(m, 'split amounts exceed total amount') then
    return 'splits-exceed-amount'
  end
  if has(m, 'too many splits') then
    return 'too-many-splits'
  end
  if (has(m, 'no matching') and has(m, 'transfer'))
    or (has(m, 'unexpected') and has(m, 'transfer')) then
    return 'no-matching-transfer'
  end
  if has(m, 'amount') and (has(m, 'mismatch') or has(m, 'does not match')) then
    return 'amount-mismatch'
  end
  if has(m, 'invalid') or has(m, 'malformed')
    or has(m, 'decode') or has(m, 'payload') then
    return 'invalid-payload'
  end
  return nil
end

-- One v1 vector to one RunnerResult; an SDK error is a classified reject.
local function result_for(vector)
  local result
  local run_ok, run_err = pcall(function()
    result = run_vector(vector)
  end)
  if not run_ok then
    -- A protocol-level rejection surfaces as outcome reject with the SDK's
    -- error message; the verifier raises either a plain string or a
    -- { code, message } table.
    local message
    if type(run_err) == 'table' then
      message = run_err.message or json.encode(run_err)
    else
      message = tostring(run_err)
    end
    result = { id = vector.id, outcome = 'reject', error = message }
    local code = classify_reject(message)
    if code ~= nil then
      result.rejectCode = code
    end
  end
  return result
end

-- Intents this runner implements; pkc checks them against
-- harness/expectations/lua.toml.
local INTENTS_JSON = '["charge","x402-exact"]'

local function encode_id(id)
  if id == nil then
    return 'null'
  end
  return json.encode(id)
end

-- Testee ABI v2 (harness/README.md): newline JSON {id, op, input} in,
-- {id, ok, result | error} out, one long-lived process. `input` is the v1
-- vector and `result` the v1 RunnerResult. The envelope is concatenated
-- around the one-shot encoding so both paths emit identical results.
local function serve()
  for line in io.stdin:lines() do
    if line:match('%S') then
      local ok, request = pcall(json.decode, line)
      local response
      if not ok or type(request) ~= 'table' then
        response = '{"id":null,"ok":false,"error":"bad-request","detail":'
          .. json.encode(tostring(request)) .. '}'
      elseif request.op == 'capabilities' then
        response = '{"id":' .. encode_id(request.id)
          .. ',"ok":true,"result":{"abi":2,"language":"lua","intents":' .. INTENTS_JSON
          .. ',"honoursClock":false}}'
      elseif request.op == 'build' or request.op == 'verify' or request.op == 'canonical-bytes' then
        -- pay_kit.configure() is once per worker; a one-shot run gets a fresh
        -- process per case, so give every served case the same fresh state.
        local loaded = package.loaded['pay_kit']
        if loaded and loaded._reset_for_tests then
          loaded._reset_for_tests()
        end
        response = '{"id":' .. encode_id(request.id)
          .. ',"ok":true,"result":' .. json.encode(result_for(request.input or {})) .. '}'
      else
        response = '{"id":' .. encode_id(request.id)
          .. ',"ok":false,"error":"unknown-op","detail":' .. json.encode(tostring(request.op)) .. '}'
      end
      io.stdout:write(response, '\n')
      io.stdout:flush()
    end
  end
end

local function main()
  for _, a in ipairs(arg or {}) do
    if a == '--serve' then
      serve()
      return
    end
  end
  local raw = read_stdin()
  raw = raw:gsub('^%s+', ''):gsub('%s+$', '')
  if raw == '' then
    io.stderr:write('lua conformance runner received empty stdin\n')
    os.exit(1)
  end

  local ok, vector = pcall(json.decode, raw)
  if not ok then
    io.stderr:write('failed to parse vector: ' .. tostring(vector) .. '\n')
    os.exit(1)
  end

  emit(result_for(vector))
end

main()
