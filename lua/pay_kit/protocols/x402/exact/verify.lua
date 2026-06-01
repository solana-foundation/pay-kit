--[[
x402 SVM-exact 11-rule structural verifier (Lua port).

Mirrors the Ruby reference at
`ruby/lib/x402/protocol/schemes/exact/verify.rb` and the Rust spine
at `rust/crates/x402/src/protocol/schemes/exact/verify.rs`. Raises
the same canonical reject strings the cross-language harness
substring-matches against.

Rules:
  1. Instruction count 3..=6                    (spine verify.rs:230-235)
  2. ix[0] = ComputeBudget SetComputeUnitLimit  (verify.rs:240-248)
  3. ix[1] = ComputeBudget SetComputeUnitPrice <= MAX (verify.rs:250-264)
  4. ix[2] = SPL TransferChecked                (verify.rs:380-410)
  5. Authority guard (no fee-payer in transfer auth) (verify.rs:382)
  6. Mint match                                 (verify.rs:395-400)
  7. Destination ATA match (re-derive)          (verify.rs:402-405)
  8. Amount match                               (verify.rs:407-410)
  9. ix[3..6] in allowlist (memo + lighthouse + optional ATA-create)
 10. Memo binding (exactly one if extra.memo set)
 11. Token program strict bind to extra.tokenProgram

Reuses lua/mpp/methods/solana/ for transaction parsing, ATA derive,
and base58. Ed25519 client-signature verification routes through
pay_kit.util.ed25519 so the openssl / luasodium backend choice
is consistent with the rest of the SDK.
]]

local base64 = require('pay_kit.util.base64_std')
local base58 = require('pay_kit.solana.base58')
local tx_mod = require('pay_kit.solana.transaction')
local ata    = require('pay_kit.solana.ata')
local ed25519 = require('pay_kit.util.ed25519')

local M = {}

local COMPUTE_BUDGET_PROGRAM    = 'ComputeBudget111111111111111111111111111111'
local MEMO_PROGRAM              = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
local LIGHTHOUSE_PROGRAM        = 'L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95'
local ASSOCIATED_TOKEN_PROGRAM  = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
local TOKEN_2022_PROGRAM        = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
local MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 50000

-- Read a little-endian u64 from a binary string at offset 1-based.
local function read_u64_le(s, start)
  if not s or #s < start + 7 then
    error('invalid_exact_svm_payload_no_transfer_instruction')
  end
  local b1, b2, b3, b4, b5, b6, b7, b8 = s:byte(start, start + 7)
  -- Use multiplication so we stay within LuaJIT 53-bit int range; SPL
  -- amounts and compute-unit prices never exceed it in practice.
  return b1 + b2 * 256 + b3 * 65536 + b4 * 16777216 +
         b5 * 4294967296 + b6 * 1099511627776 + b7 * 281474976710656 +
         b8 * 72057594037927936
end

-- Look up the program id (base58 string) for an instruction.
local function program_of(account_keys, ix)
  local idx = ix.program_id_index + 1
  return account_keys[idx]
end

local function account_at(account_keys, ix, slot)
  return account_keys[ix.accounts[slot + 1] + 1]
end

-- Rule 2: ix[0] = ComputeBudget SetComputeUnitLimit.
local function verify_compute_limit(ix, account_keys)
  local data = ix.data
  if program_of(account_keys, ix) ~= COMPUTE_BUDGET_PROGRAM
      or #data ~= 5 or data:byte(1) ~= 2 then
    error('invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction')
  end
end

-- Rule 3: ix[1] = ComputeBudget SetComputeUnitPrice <= MAX.
local function verify_compute_price(ix, account_keys)
  local data = ix.data
  if program_of(account_keys, ix) ~= COMPUTE_BUDGET_PROGRAM
      or #data ~= 9 or data:byte(1) ~= 3 then
    error('invalid_exact_svm_payload_transaction_instructions_compute_price_instruction')
  end
  local micro = read_u64_le(data, 2)
  if micro > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS then
    error('invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high')
  end
end

-- Decode a base58 requirement field (e.g. asset, payTo) once.
local function b58_field(requirement, key)
  local v = requirement[key]
  if type(v) ~= 'string' or v == '' then
    error('invalid_exact_svm_payload_missing_field_' .. key)
  end
  return v
end

local function string_extra(requirement, key, required)
  local extra = requirement.extra or {}
  local v = extra[key]
  if (v == nil or v == '') and required then
    error('invalid_exact_svm_payload_missing_extra_' .. key)
  end
  return v
end

-- Rules 4 + 5 + 6 + 7 + 8 + 11 in one pass on the TransferChecked
-- instruction.
local function verify_transfer(ix, account_keys, requirement, managed_signers)
  local program = program_of(account_keys, ix)
  local token_program_extra = string_extra(requirement, 'tokenProgram', true)
  if program ~= token_program_extra and program ~= TOKEN_2022_PROGRAM then
    error('invalid_exact_svm_payload_no_transfer_instruction')
  end
  local data = ix.data
  if #ix.accounts < 4 or #data ~= 10 or data:byte(1) ~= 12 then
    error('invalid_exact_svm_payload_no_transfer_instruction')
  end
  local source      = account_at(account_keys, ix, 0)
  local mint        = account_at(account_keys, ix, 1)
  local destination = account_at(account_keys, ix, 2)
  local authority   = account_at(account_keys, ix, 3)

  -- Rule 5: authority guard.
  for i = 1, #managed_signers do
    if managed_signers[i] == authority or managed_signers[i] == source then
      error('invalid_exact_svm_payload_transaction_fee_payer_transferring_funds')
    end
  end
  for j = 1, #ix.accounts do
    local key = account_keys[ix.accounts[j] + 1]
    for i = 1, #managed_signers do
      if managed_signers[i] == key then
        error('invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts')
      end
    end
  end

  -- Rule 6: mint match.
  local expected_mint = b58_field(requirement, 'asset')
  if mint ~= expected_mint then
    error('invalid_exact_svm_payload_mint_mismatch')
  end

  -- Rule 7: destination ATA match.
  local pay_to = b58_field(requirement, 'payTo')
  local expected_destination = ata.derive(pay_to, expected_mint, program)
  if destination ~= expected_destination then
    error('invalid_exact_svm_payload_recipient_mismatch')
  end

  -- Rule 8: amount match.
  local amount = read_u64_le(data, 2)
  local expected_amount = tonumber(b58_field(requirement, 'amount')) or
    tonumber(requirement.maxAmountRequired or '')
  if amount ~= expected_amount then
    error('invalid_exact_svm_payload_amount_mismatch')
  end

  return {
    program     = program,
    source      = source,
    mint        = mint,
    destination = destination,
    authority   = authority,
    amount      = amount,
  }
end

-- Optional ATA-create slot (intentional divergence from spine to
-- allow buyer-funded destination ATA creation in slots 3-4).
local function valid_ata_create(ix, account_keys, requirement, transfer)
  if program_of(account_keys, ix) ~= ASSOCIATED_TOKEN_PROGRAM then return false end
  -- The ATA-create instruction's accounts (per the SPL Associated
  -- Token Program): [payer, ata, owner, mint, system, token_program]
  -- with discriminator 0 (Create) or 1 (CreateIdempotent) in data[0].
  local data = ix.data
  if #data < 1 or (data:byte(1) ~= 0 and data:byte(1) ~= 1) then return false end
  if #ix.accounts < 6 then return false end
  local ata_account = account_at(account_keys, ix, 1)
  local owner       = account_at(account_keys, ix, 2)
  local mint        = account_at(account_keys, ix, 3)
  local expected_owner = requirement.payTo
  if owner ~= expected_owner then return false end
  if mint ~= transfer.mint then return false end
  if ata_account ~= transfer.destination then return false end
  return true
end

local function find_memo_match(account_keys, instructions, expected_memo)
  local memo_count, last_memo_data = 0, nil
  for i = 4, #instructions do
    if program_of(account_keys, instructions[i]) == MEMO_PROGRAM then
      memo_count = memo_count + 1
      last_memo_data = instructions[i].data
    end
  end
  if memo_count ~= 1 then
    error('invalid_exact_svm_payload_memo_count')
  end
  if last_memo_data ~= expected_memo then
    error('invalid_exact_svm_payload_memo_mismatch')
  end
end

-- Top-level: verify a base64-encoded transaction against a server
-- offer. `managed_signers` is the list of base58 keys the server has
-- authority over (the operator's pubkey at minimum); the verifier
-- refuses to treat any of those as the transfer source / authority
-- so a malicious credential cannot "spend the facilitator's funds".
function M.verify(transaction_b64, requirement, managed_signers)
  local decode_ok, raw = pcall(base64.decode, transaction_b64)
  if not decode_ok or not raw or raw == '' then
    error('invalid_exact_svm_payload_base64')
  end
  local ok, parsed_or_err = pcall(tx_mod.from_bytes, raw)
  if not ok then error('invalid_exact_svm_payload_transaction_parse') end
  local parsed = parsed_or_err

  local instructions = parsed.message.instructions
  if #instructions < 3 or #instructions > 6 then
    error('invalid_exact_svm_payload_transaction_instructions_length')
  end

  verify_compute_limit(instructions[1], parsed.message.account_keys)
  verify_compute_price(instructions[2], parsed.message.account_keys)
  local transfer = verify_transfer(instructions[3], parsed.message.account_keys,
                                   requirement, managed_signers)

  -- Rule 9: slots 3..6 allowlist.
  local destination_create_ata = false
  local reasons = {
    'invalid_exact_svm_payload_unknown_fourth_instruction',
    'invalid_exact_svm_payload_unknown_fifth_instruction',
    'invalid_exact_svm_payload_unknown_sixth_instruction',
  }
  for i = 4, #instructions do
    local ix = instructions[i]
    local program = program_of(parsed.message.account_keys, ix)
    local slot_index = i - 4  -- 0-based offset within slots 3..5
    local allowed = (program == MEMO_PROGRAM) or
      (slot_index < 2 and program == LIGHTHOUSE_PROGRAM)
    if not allowed and slot_index < 2 and
        valid_ata_create(ix, parsed.message.account_keys, requirement, transfer) then
      destination_create_ata = true
      allowed = true
    end
    if not allowed then
      error(reasons[slot_index + 1] or 'invalid_exact_svm_payload_unknown_optional_instruction')
    end
  end

  -- Rule 10: memo binding.
  local expected_memo = string_extra(requirement, 'memo', false)
  if expected_memo and expected_memo ~= '' then
    find_memo_match(parsed.message.account_keys, instructions, expected_memo)
  end

  transfer.destination_create_ata = destination_create_ata
  return transfer
end

-- Verify non-managed client signatures on the transaction envelope.
-- Mirrors Ruby `verify_client_signatures!`. The transaction bytes
-- carry [signatures... | message]; the server-managed signers
-- (facilitator pubkey) are skipped because the facilitator signs
-- after verification.
function M.verify_client_signatures(transaction_b64, managed_signer_b58_list)
  local decode_ok, raw = pcall(base64.decode, transaction_b64)
  if not decode_ok or not raw or raw == '' then
    error('invalid_exact_svm_payload_signature')
  end

  -- compact-u16 short-vec at offset 0 = signature count.
  local function read_short_vec(bytes, offset)
    local value, shift = 0, 0
    local i = offset + 1
    repeat
      local b = bytes:byte(i)
      if not b then error('invalid_exact_svm_payload_signature') end
      value = value + (b % 128) * (2 ^ shift)
      i = i + 1
      shift = shift + 7
    until b < 128
    return value, i - 1
  end

  local signature_count, signatures_offset = read_short_vec(raw, 0)
  local message_offset = signatures_offset + (signature_count * 64)
  if message_offset >= #raw then
    error('invalid_exact_svm_payload_signature')
  end
  local message = raw:sub(message_offset + 1)
  if message:byte(1) ~= 0x80 then
    error('invalid_exact_svm_payload_signature')
  end
  local required_signatures = message:byte(2)
  if required_signatures > signature_count then
    error('invalid_exact_svm_payload_signature')
  end
  local account_count, account_offset = read_short_vec(message, 4)
  if required_signatures > account_count then
    error('invalid_exact_svm_payload_signature')
  end

  local zero_sig = string.rep(string.char(0), 64)
  local managed_set = {}
  for i = 1, #managed_signer_b58_list do
    managed_set[managed_signer_b58_list[i]] = true
  end

  for index = 0, required_signatures - 1 do
    local signer_key_start = account_offset + (index * 32) + 1
    if signer_key_start + 31 > #message then
      error('invalid_exact_svm_payload_signature')
    end
    local signer_key_bytes = message:sub(signer_key_start, signer_key_start + 31)
    local signer_key_b58 = base58.encode(signer_key_bytes)
    if not managed_set[signer_key_b58] then
      local sig = raw:sub(signatures_offset + (index * 64) + 1,
                          signatures_offset + (index * 64) + 64)
      if sig == zero_sig then
        error('invalid_exact_svm_payload_signature')
      end
      local ok = ed25519.verify(signer_key_bytes, message, sig)
      if not ok then
        error('invalid_exact_svm_payload_signature')
      end
    end
  end
end

return M
