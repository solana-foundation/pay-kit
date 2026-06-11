-- Lua cross-SDK conformance-vector runner.
--
-- Honors the same stdin/stdout contract as the TypeScript reference runner
-- (harness/src/conformance/ts-runner.ts) and the Go runner
-- (go/cmd/conformance/main.go): read one conformance vector as JSON on
-- stdin, drive the real Lua pay_kit SDK for the requested mode, and emit
-- one RunnerResult line as JSON on stdout.
--
-- ROLE: the Lua SDK is SERVER-ONLY. It ships a pre-broadcast charge
-- verifier (pay_kit.solana.verifier) and the wire canonical-JSON /
-- base64url encoders, but no client-side transaction builder. The runner
-- therefore supports:
--   * canonical-bytes  -- JCS (RFC 8785) + base64url + fixed-width bytes
--   * verify-transaction WHEN the vector ships a concrete `transaction`
--     base64 (the pure pre-broadcast checks: no live RPC, no HMAC)
-- Build-transaction vectors, and verify-transaction vectors that expect
-- the runner to BUILD the transaction first, have no server-only
-- equivalent. For those the runner emits a clear "unsupported-mode"
-- reject so the driver SKIPs (not fails) the vector for Lua.
--
-- It also handles the x402 `exact` intent (v2): build vectors emit
-- unsupported-mode (server-only SDK, no client builder), and verify
-- vectors drive the real pay_kit.protocols.x402 credential decoder to
-- emit accept/reject (+ rejectCode) plus the decoded X402EnvelopeShape.
--
-- The run is deterministic and RPC-free: the verifier decodes the wire
-- bytes locally and never contacts a validator. A vector that would
-- require a live RPC call is, by construction, a build vector this runner
-- already refuses.
--
-- Run from the `lua/` directory so the `./?.lua` / `./?/init.lua` package
-- path resolves the pay_kit tree (see tests/run.lua and the RUNNER_CWD
-- entry in harness/test/conformance.test.ts).

package.path = table.concat({
  './?.lua',
  './?/init.lua',
  package.path,
}, ';')

local json = require('pay_kit.util.json')
local base64url = require('pay_kit.util.base64url')
local base64_std = require('pay_kit.util.base64_std')
local challenge = require('pay_kit.protocol.core.challenge')
local verifier = require('pay_kit.solana.verifier')
local transaction = require('pay_kit.solana.transaction')
local instructions = require('pay_kit.solana.instructions')
local base58 = require('pay_kit.solana.base58')
local ata = require('pay_kit.solana.ata')
local mints = require('pay_kit.solana.mints')

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

-- Apply the same precedence rules as the TS / Go reference runners:
-- top-level `asset` / `payTo` win over `currency` / `recipient`, and the
-- methodDetails carry network / decimals / tokenProgram / splits /
-- feePayer. The Lua verifier consumes a request table shaped exactly like
-- the live charge route's decoded request, so we mirror that shape here.
local function flatten_request(req)
  local currency = req.currency
  if req.asset ~= nil and req.asset ~= json.null then
    currency = req.asset
  end
  local recipient = req.recipient
  if req.payTo ~= nil and req.payTo ~= json.null then
    recipient = req.payTo
  end

  local md = req.methodDetails or {}
  local network = md.network
  if network == nil or network == json.null then
    network = 'mainnet'
  end

  local details = { network = network }
  -- decimals: the verifier types it as Option<u8>; keep it numeric when
  -- the vector pins it, leave nil otherwise so the verifier's "any
  -- decimals" branch applies (it never injects a default).
  if type(md.decimals) == 'number' then
    details.decimals = md.decimals
  end
  if type(md.tokenProgram) == 'string' then
    details.tokenProgram = md.tokenProgram
  end
  if md.feePayer == true then
    details.feePayer = true
  end
  if type(md.feePayerKey) == 'string' then
    details.feePayerKey = md.feePayerKey
  end
  if type(md.splits) == 'table' then
    details.splits = md.splits
  end

  local request = {
    amount = req.amount,
    currency = currency,
    recipient = recipient,
    methodDetails = details,
  }
  if type(req.externalId) == 'string' and req.externalId ~= '' then
    request.externalId = req.externalId
  end
  return request
end

-- ── wire transaction fixture builder ──
--
-- The Lua SDK is server-only: the verifier is the system under test, and a
-- verify vector that omits `input.transaction` only pins the request +
-- signer, expecting the runner to assemble the wire fixture the verifier
-- then accepts. This mirrors the Ruby runner's TxFixtureBuilder and lays
-- out instructions exactly how the Rust client builder emits them and the
-- Lua verifier reads them: transferChecked accounts (source, mint, dest,
-- authority); idempotent ATA create accounts (payer, ata, owner, mint,
-- system, token program); memo program data is the raw memo bytes. No RPC,
-- no signature: the verifier checks transaction shape, not signatures.

-- Encode an unsigned decimal-string value as `width` little-endian bytes.
local function le_bytes(value, width)
  local digits = {}
  local text = tostring(value)
  if not text:match('^%d+$') then
    error('invalid unsigned integer: ' .. text)
  end
  for i = 1, #text do
    digits[i] = tonumber(text:sub(i, i))
  end
  local out = {}
  for _ = 1, width do
    -- Long division of the decimal digit array by 256 collects one byte.
    local remainder = 0
    local next_digits = {}
    local started = false
    for i = 1, #digits do
      local acc = remainder * 10 + digits[i]
      local q = math.floor(acc / 256)
      remainder = acc % 256
      if started or q ~= 0 then
        next_digits[#next_digits + 1] = q
        started = true
      end
    end
    if #next_digits == 0 then
      next_digits = { 0 }
    end
    out[#out + 1] = string.char(remainder)
    digits = next_digits
  end
  for i = 1, #digits do
    if digits[i] ~= 0 then
      error('value does not fit in ' .. width .. ' bytes')
    end
  end
  return table.concat(out)
end

-- Build a verify-transaction wire fixture from a flattened request and the
-- vector's 64-byte signer secret key. Returns a standard base64 string.
local function build_fixture(flat, signer_secret)
  if #signer_secret ~= 64 then
    error('signerSecretKey must be 64 bytes')
  end
  -- The public key is the trailing 32 bytes of the ed25519 secret key.
  local pub_bytes = {}
  for i = 33, 64 do
    pub_bytes[#pub_bytes + 1] = string.char(signer_secret[i])
  end
  local signer = base58.encode(table.concat(pub_bytes))

  local details = flat.methodDetails or {}
  local currency = flat.currency
  local recipient = flat.recipient
  local network = details.network or 'mainnet'
  local is_sol = type(currency) == 'string' and currency:upper() == 'SOL'

  local splits = details.splits or {}
  local total = tonumber(flat.amount)
  local split_total = 0
  for i = 1, #splits do
    split_total = split_total + tonumber(splits[i].amount)
  end
  local primary = total - split_total

  -- Instruction list: { program = base58, accounts = { base58... }, data = raw }
  local ixs = {}
  local function add_ix(program, accounts, data)
    ixs[#ixs + 1] = { program = program, accounts = accounts, data = data }
  end

  if is_sol then
    add_ix(SYSTEM_PROGRAM, { signer, recipient },
      le_bytes(2, 4) .. le_bytes(primary, 8))
    for i = 1, #splits do
      add_ix(SYSTEM_PROGRAM, { signer, splits[i].recipient },
        le_bytes(2, 4) .. le_bytes(splits[i].amount, 8))
      if splits[i].memo and splits[i].memo ~= '' then
        add_ix(MEMO_PROGRAM, {}, splits[i].memo)
      end
    end
  else
    local mint = mints.resolve_mint(currency, network) or currency
    local token_program = details.tokenProgram
      or mints.default_token_program_for_currency(currency, network)
    local decimals = details.decimals or 6
    local source_ata = ata.derive(signer, mint, token_program)
    local dest_ata = ata.derive(recipient, mint, token_program)
    add_ix(token_program, { source_ata, mint, dest_ata, signer },
      string.char(12) .. le_bytes(primary, 8) .. string.char(decimals))
    for i = 1, #splits do
      local sr = splits[i].recipient
      local sata = ata.derive(sr, mint, token_program)
      if splits[i].ataCreationRequired == true then
        add_ix(instructions.ASSOCIATED_TOKEN_PROGRAM,
          { signer, sata, sr, mint, SYSTEM_PROGRAM, token_program },
          string.char(1))
      end
      add_ix(token_program, { source_ata, mint, sata, signer },
        string.char(12) .. le_bytes(splits[i].amount, 8) .. string.char(decimals))
      if splits[i].memo and splits[i].memo ~= '' then
        add_ix(MEMO_PROGRAM, {}, splits[i].memo)
      end
    end
  end

  -- Account key set: signer (lone signer / fee payer) at index 0, then every
  -- instruction account and program id in first-seen order. The verifier
  -- reads layout by index, so a single read-only-unsigned tail suffices.
  local keys = { signer }
  local seen = { [signer] = true }
  local function push_key(k)
    if not seen[k] then
      seen[k] = true
      keys[#keys + 1] = k
    end
  end
  for _, ix in ipairs(ixs) do
    for _, a in ipairs(ix.accounts) do
      push_key(a)
    end
    push_key(ix.program)
  end
  local index = {}
  for i, k in ipairs(keys) do
    index[k] = i - 1
  end

  local blockhash = details.recentBlockhash or string.rep('1', 32)
  local ok, blockhash_bytes = pcall(base58.decode, blockhash)
  if not ok or #blockhash_bytes ~= 32 then
    blockhash_bytes = base58.decode(string.rep('1', 32))
  end

  local signer_count = 1
  local readonly_unsigned = #keys - 1

  local parts = {}
  parts[#parts + 1] = string.char(signer_count, 0, readonly_unsigned)
  parts[#parts + 1] = transaction.compact_u16(#keys)
  for _, k in ipairs(keys) do
    parts[#parts + 1] = base58.decode(k)
  end
  parts[#parts + 1] = blockhash_bytes
  parts[#parts + 1] = transaction.compact_u16(#ixs)
  for _, ix in ipairs(ixs) do
    parts[#parts + 1] = string.char(index[ix.program])
    parts[#parts + 1] = transaction.compact_u16(#ix.accounts)
    for _, a in ipairs(ix.accounts) do
      parts[#parts + 1] = string.char(index[a])
    end
    parts[#parts + 1] = transaction.compact_u16(#ix.data)
    parts[#parts + 1] = ix.data
  end
  local message = table.concat(parts)

  local signatures = transaction.compact_u16(signer_count)
    .. string.rep(string.char(0), 64 * signer_count)
  return base64_std.encode(signatures .. message)
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

-- verify-transaction: the Lua SDK is server-only, so the verifier is the
-- system under test. When the vector pins a concrete `transaction` the
-- runner verifies it directly; when it omits one (pinning only request +
-- signerSecretKey) the runner assembles the wire fixture itself via
-- build_fixture, exactly as the Ruby runner does, then runs the verifier
-- over it. Either way the SDK verifier is what is exercised.
local function run_verify_transaction(vector)
  local input = vector.input or {}
  if type(input.request) ~= 'table' then
    error('verify vector is missing input.request')
  end
  local request = flatten_request(input.request)

  local tx = input.transaction
  if type(tx) ~= 'string' or tx == '' then
    if type(input.signerSecretKey) ~= 'table' then
      error('verify vector without input.transaction is missing input.signerSecretKey')
    end
    tx = build_fixture(request, input.signerSecretKey)
  end

  -- Pure pre-broadcast structural verify: decode the wire bytes and assert
  -- the charge shape. No RPC, no HMAC, no broadcast.
  verifier.verify_transaction_base64(tx, request)
  return {
    id = vector.id,
    outcome = 'accept',
    transactionShape = shape_from_transaction(tx),
  }
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

-- ── x402 `exact` intent (v2) ──
--
-- The x402 charge is HTTP-shaped, not transaction-shaped: a CLIENT build
-- produces a base64(JSON) payment header and a SERVER verify consumes one.
-- The cross-SDK oracle is therefore the DECODED ENVELOPE shape, not the
-- signed Solana transaction inside `payload.transaction` (that is the
-- harness matrix's job). This mirrors the TS reference
-- (harness/src/conformance/x402.ts) and the Rust spine line-for-line.
--
-- The Lua SDK is SERVER-only, so:
--   * build-transaction (x402) -> unsupported-mode (driver SKIPs).
--   * verify-transaction (x402) -> run the server-side credential decode
--     (version dispatch + per-version network gate) + the v2 accepted-vs-
--     route field comparison, emit accept/reject (+ rejectCode), and
--     surface the decoded X402EnvelopeShape on accept.
--
-- The version dispatch, network gate, and CAIP-2 normalization below
-- mirror pay_kit.protocols.x402 (init.lua decode_payment_signature /
-- caip2_network_for_cluster) line-for-line, which in turn mirrors the
-- Rust spine (parse_payment_signature + verify_envelope_payload). They
-- are inlined here rather than required so the runner stays self-contained
-- under a bare luajit invocation (the x402 adapter module pulls in
-- cjson/rpc/cosocket dependencies the conformance harness does not load),
-- exactly as the charge path uses pay_kit.util.json over cjson.

local CAIP2_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
local CAIP2_DEVNET  = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'
local LEGACY_NETWORK_SOLANA = 'solana'
local LEGACY_NETWORK_DEVNET = 'solana-devnet'

-- x402 v2 `payment-identifier` extension (rust types.rs PaymentExtensions:
-- #[serde(rename = "payment-identifier")]). The id must match the spec
-- pattern ^[A-Za-z0-9_-]{16,128}$ (rust PaymentIdentifierInfo / coinbase
-- payment_identifier.md §5.1.2).
local PAYMENT_IDENTIFIER_KEY = 'payment-identifier'

-- Lua patterns lack regex quantifier bounds, so mirror ^[A-Za-z0-9_-]{16,128}$
-- with an explicit character-class match plus a length window.
local function payment_identifier_id_valid(id)
  if type(id) ~= 'string' then return false end
  if #id < 16 or #id > 128 then return false end
  return id:match('^[A-Za-z0-9_%-]+$') ~= nil
end

-- Normalize any network identifier (CAIP-2 or legacy slug) to its CAIP-2
-- form. Mirrors rust caip2_network_for_cluster (types.rs) and the SDK's
-- pay_kit.protocols.x402 caip2_network_for_cluster.
local function caip2_network_for_cluster(network)
  if type(network) ~= 'string' then return '' end
  if network == LEGACY_NETWORK_SOLANA or network == 'mainnet'
    or network == 'mainnet-beta' or network == CAIP2_MAINNET then
    return CAIP2_MAINNET
  end
  if network == LEGACY_NETWORK_DEVNET or network == 'devnet'
    or network == 'localnet' or network == CAIP2_DEVNET then
    return CAIP2_DEVNET
  end
  return network
end

-- Decode the base64(JSON) payment header into the conformance envelope
-- shape oracle. Mirrors decodeEnvelopeShape in the TS reference: presence
-- of top-level scheme/network and accepted is part of the contract (v1
-- carries scheme+network and no accepted; v2 carries accepted and no
-- top-level scheme/network). Only keys actually present on the wire are
-- set, so the JSON encoder omits the rest and the driver reads them as
-- absent.
local function decode_envelope_shape(header)
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

-- verify-transaction (x402): decode the credential, run the version
-- dispatch + per-version network gate (mirroring the SDK's
-- decode_payment_signature / the rust parse_payment_signature), then for
-- v2 also run the accepted-vs-route field comparison (amount / payTo /
-- asset) the rust verify_envelope_payload + TS reference verifyPaymentHeader
-- apply. RPC-free: the signed-transaction settlement is out of scope for
-- the envelope oracle, so a structurally valid, route-matching envelope is
-- accepted. Raises on reject so the shared classifier maps the message
-- onto a RejectCode.
local function run_x402_verify(vector)
  local input = vector.input or {}
  local header = input.x402PaymentHeader
  if type(header) ~= 'string' or header == '' then
    error('invalid payload: x402 verify vector missing input.x402PaymentHeader')
  end
  if input.x402ServerNetwork == nil
    or input.x402ServerRecipient == nil
    or input.x402ServerCurrency == nil
    or input.x402ServerAmount == nil then
    error('invalid payload: x402 verify vector missing server route')
  end

  local expected_caip2 = caip2_network_for_cluster(input.x402ServerNetwork)

  local decoded = base64_std.decode(header)
  if not decoded then
    error('invalid payload: payment-signature base64 decode failed')
  end
  local env = json.decode(decoded)
  if type(env) ~= 'table' then
    error('invalid payload: payment-signature not a JSON object')
  end

  local version = env.x402Version
  if version == 1 then
    -- Legacy v1 dual-accept arm. The v1 envelope carries scheme + network
    -- as top-level siblings of payload (no accepted object), so the server
    -- binds only scheme + network and normalizes the plain SVM slug via
    -- caip2_network_for_cluster before the network gate. Mirrors the rust
    -- parse_payment_signature v1 arm (server/exact.rs:316-327): there is no
    -- accepted-vs-route field comparison because v1 has no accepted object.
    local scheme = env.scheme
    if scheme ~= 'exact' then
      error('invalid payload: v1 envelope scheme is not exact')
    end
    if caip2_network_for_cluster(env.network or '') ~= expected_caip2 then
      error('wrong network: credential network does not match server')
    end
  elseif version == 2 then
    local accepted = env.accepted
    if type(accepted) ~= 'table' then
      error('invalid payload: v2 envelope missing accepted')
    end
    if caip2_network_for_cluster(accepted.network or '') ~= expected_caip2 then
      error('wrong network: credential network does not match server')
    end
    -- accepted-vs-route field comparison (rust verify_envelope_payload).
    if tostring(accepted.amount or '') ~= tostring(input.x402ServerAmount) then
      error('Amount mismatch: expected ' .. tostring(input.x402ServerAmount)
        .. ', got ' .. tostring(accepted.amount))
    end
    if tostring(accepted.payTo or '') ~= tostring(input.x402ServerRecipient) then
      error('Recipient mismatch: credential claims a different recipient')
    end
    if tostring(accepted.asset or '') ~= tostring(input.x402ServerCurrency) then
      error('Currency mismatch: expected ' .. tostring(input.x402ServerCurrency)
        .. ', got ' .. tostring(accepted.asset))
    end
    -- Extensions reject gate (rust PaymentExtensions::requires_payment_identifier
    -- + the coinbase spec's 400 when required-and-missing; TS reference
    -- verifyPaymentHeader). When the route requires a payment-identifier, the
    -- echoed credential MUST carry a valid pay_-shaped id. Missing, empty, or
    -- pattern-violating ids reject as payment-identifier-required.
    if input.x402ServerRequiresPaymentIdentifier == true then
      local extensions = env.extensions
      local pid = type(extensions) == 'table' and extensions[PAYMENT_IDENTIFIER_KEY] or nil
      local id = type(pid) == 'table' and type(pid.info) == 'table' and pid.info.id or nil
      if id == nil or id == '' then
        error('payment-identifier required but credential echoed no id')
      end
      if not payment_identifier_id_valid(id) then
        error('payment-identifier id is invalid: ' .. tostring(id)
          .. ' does not match ^[A-Za-z0-9_-]{16,128}$')
      end
    end
  else
    error('invalid payload: unsupported x402Version ' .. tostring(version))
  end

  -- Payload must carry a transaction proof (envelope oracle only checks
  -- presence; the signed-transaction settlement is the harness matrix's job).
  local payload = env.payload
  if type(payload) ~= 'table'
    or type(payload.transaction) ~= 'string'
    or payload.transaction == '' then
    error('invalid payload: missing transaction proof')
  end

  return {
    id = vector.id,
    outcome = 'accept',
    x402EnvelopeShape = decode_envelope_shape(header),
  }
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

local function main()
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

  emit(result)
end

main()
