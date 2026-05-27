--[[
P5-late x402 11-rule structural verifier — positive-path test.

Constructs a minimal but valid versioned transaction (compute-limit,
compute-price, transferChecked, memo) and verifies it against a
matching server offer. The structural verify path runs end-to-end:
account-key indexing, ATA re-derive, mint + amount + memo match.
The client-signature check is tested separately - this case uses
zero-byte signature placeholders because the rule-set verifier
doesn't read sig bytes (Ed25519 validation lives in
`verify_client_signatures`).

Negative paths live in `x402_verify_spec.lua`.
]]

local helper = require('tests.test_helper')
local base64 = require('pay_kit.util.base64_std')
local base58 = require('pay_kit.solana.base58')
local tx_mod = require('pay_kit.solana.transaction')
local ata    = require('pay_kit.solana.ata')
local x402_verify = require('pay_kit.protocols.x402.exact.verify')

-- --- bincode-style serializers --------------------------------------

local function u64_le(n)
  local out = {}
  for _ = 1, 8 do
    out[#out + 1] = string.char(n % 256)
    n = math.floor(n / 256)
  end
  return table.concat(out)
end

local function u32_le(n)
  local out = {}
  for _ = 1, 4 do
    out[#out + 1] = string.char(n % 256)
    n = math.floor(n / 256)
  end
  return table.concat(out)
end

-- --- transaction synthesis -----------------------------------------

local COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111'
local MEMO_PROGRAM   = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
local TOKEN_PROGRAM  = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'

-- Construct a synthetic v0 transaction whose first three instructions
-- match the x402 SVM-exact rule set. Returns (raw_bytes, message_bytes).
-- Account-key order is:
--   [0] facilitator (the managed signer; cannot be transfer authority)
--   [1] source ATA       (transfer authority's token account)
--   [2] mint
--   [3] destination ATA  (re-derived from owner+mint+program)
--   [4] authority        (transfer signer, distinct from facilitator)
--   [5] ComputeBudget program
--   [6] token program
--   [7] Memo program
local function synthesize_tx(facilitator, source, mint, destination, authority, amount, memo)
  -- Header: required_signatures = 1 (facilitator), readonly_signed = 0,
  -- readonly_unsigned = 3 (compute-budget, token-program, memo).
  local header = string.char(1, 0, 3)

  local account_count = tx_mod.compact_u16(8)
  local account_keys = {
    base58.decode(facilitator),
    base58.decode(source),
    base58.decode(mint),
    base58.decode(destination),
    base58.decode(authority),
    base58.decode(COMPUTE_BUDGET),
    base58.decode(TOKEN_PROGRAM),
    base58.decode(MEMO_PROGRAM),
  }
  local account_keys_blob = table.concat(account_keys)

  local recent_blockhash = string.rep('\0', 32)

  local function build_ix(program_index, accounts, data)
    local out = {string.char(program_index)}
    out[#out + 1] = tx_mod.compact_u16(#accounts)
    for i = 1, #accounts do out[#out + 1] = string.char(accounts[i]) end
    out[#out + 1] = tx_mod.compact_u16(#data)
    out[#out + 1] = data
    return table.concat(out)
  end

  local ix_limit    = build_ix(5, {}, string.char(2) .. u32_le(200000))
  local ix_price    = build_ix(5, {}, string.char(3) .. u64_le(1000))
  local ix_transfer = build_ix(6, {1, 2, 3, 4}, string.char(12) .. u64_le(amount) .. string.char(6))
  local ix_memo     = build_ix(7, {}, memo)

  local instructions_blob = table.concat({
    tx_mod.compact_u16(4),
    ix_limit, ix_price, ix_transfer, ix_memo,
  })

  -- v0 has a trailing address-table-lookups vector (we use empty).
  local lookups = tx_mod.compact_u16(0)

  local message = table.concat({
    '\x80', header, account_count, account_keys_blob,
    recent_blockhash, instructions_blob, lookups,
  })

  -- One zero-byte signature placeholder for the facilitator slot.
  -- (The structural verifier does NOT read signature bytes; the
  -- Ed25519 validation runs in `verify_client_signatures`.)
  local signature_count = tx_mod.compact_u16(1)
  local signatures = string.rep('\0', 64)

  local envelope = signature_count .. signatures .. message
  return envelope
end

-- --- positive case --------------------------------------------------

helper.test('verify accepts a structurally-valid transferChecked envelope', function()
  -- Use a synthetic facilitator key (32 zero bytes is a valid Solana
  -- pubkey for the purposes of structural verification - the test
  -- does not invoke Ed25519).
  local facilitator = base58.encode(string.rep('\1', 32))
  local authority   = base58.encode(string.rep('\2', 32))
  local source      = base58.encode(string.rep('\3', 32))
  local mint        = base58.encode(string.rep('\4', 32))

  -- Compute the destination ATA the verifier will re-derive.
  local pay_to = base58.encode(string.rep('\5', 32))
  local destination = ata.derive(pay_to, mint, TOKEN_PROGRAM)

  local amount = 1000
  local memo   = '/paid'
  local raw    = synthesize_tx(facilitator, source, mint, destination,
                               authority, amount, memo)

  local offer = {
    scheme = 'exact', network = 'solana:dev',
    asset  = mint, amount = tostring(amount), payTo = pay_to,
    extra  = {feePayer = facilitator, decimals = 6,
              tokenProgram = TOKEN_PROGRAM, memo = memo},
  }

  local transfer = x402_verify.verify(base64.encode(raw), offer, {facilitator})
  helper.assert_true(transfer ~= nil, 'expected verify to return a transfer descriptor')
  helper.assert_equal(transfer.mint, mint)
  helper.assert_equal(transfer.destination, destination)
  helper.assert_equal(transfer.amount, amount)
  helper.assert_equal(transfer.authority, authority)
end)

-- --- negative: amount mismatch (uses the same synth path) ----------

helper.test('verify rejects amount mismatch via the structural pass', function()
  local facilitator = base58.encode(string.rep('\1', 32))
  local authority   = base58.encode(string.rep('\2', 32))
  local source      = base58.encode(string.rep('\3', 32))
  local mint        = base58.encode(string.rep('\4', 32))
  local pay_to      = base58.encode(string.rep('\5', 32))
  local destination = ata.derive(pay_to, mint, TOKEN_PROGRAM)

  local raw = synthesize_tx(facilitator, source, mint, destination,
                            authority, 999, '/paid')
  local offer = {
    scheme = 'exact', network = 'solana:dev',
    asset = mint, amount = '1000', payTo = pay_to,
    extra = {feePayer = facilitator, decimals = 6,
             tokenProgram = TOKEN_PROGRAM, memo = '/paid'},
  }
  local ok, err = pcall(x402_verify.verify, base64.encode(raw), offer, {facilitator})
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('amount_mismatch', 1, true), tostring(err))
end)

helper.test('verify rejects authority that matches a managed signer', function()
  local facilitator = base58.encode(string.rep('\1', 32))
  -- Authority IS the facilitator - the verifier's rule 5 must reject.
  local source = base58.encode(string.rep('\3', 32))
  local mint   = base58.encode(string.rep('\4', 32))
  local pay_to = base58.encode(string.rep('\5', 32))
  local destination = ata.derive(pay_to, mint, TOKEN_PROGRAM)

  local raw = synthesize_tx(facilitator, source, mint, destination,
                            facilitator, 1000, '/paid')
  local offer = {
    scheme = 'exact', network = 'solana:dev',
    asset = mint, amount = '1000', payTo = pay_to,
    extra = {feePayer = facilitator, decimals = 6,
             tokenProgram = TOKEN_PROGRAM, memo = '/paid'},
  }
  local ok, err = pcall(x402_verify.verify, base64.encode(raw), offer, {facilitator})
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('fee_payer', 1, true), tostring(err))
end)
