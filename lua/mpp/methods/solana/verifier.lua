--[[
Real Solana charge-credential verifier for the Lua MPP server.

This module is the runtime counterpart of
`ruby/lib/mpp/methods/solana/verifier.rb`. It takes the base64-encoded
transaction the client posted as the `Authorization: Payment`
credential, decodes it through the codec / instruction parsers / ATA
derivation modules this PR ships, and rejects on the first shape
mismatch the Rust spine rejects. The accepting path returns silently
and the surrounding `mpp.server.charge_handler` proceeds with cosign /
simulate / broadcast / consume / await.

The verifier replaces the hooks-based shape in
`mpp.server.solana_verify.new_signature_verifier`, which delegates
parsing to caller-supplied hooks. The hooks-based path is preserved
for backward compatibility; callers opt into the real verifier with
`mpp.server.solana_verify.new_real_verifier(opts)`.
]]

local uint = require('mpp.util.uint')
local transaction = require('mpp.methods.solana.transaction')
local instructions = require('mpp.methods.solana.instructions')
local ata = require('mpp.methods.solana.ata')
local protocol = require('mpp.protocol.solana')
local error_codes = require('mpp.protocol.core.error_codes')

local M = {}

local TOKEN_PROGRAM = instructions.TOKEN_PROGRAM
local TOKEN_2022_PROGRAM = instructions.TOKEN_2022_PROGRAM
local SYSTEM_PROGRAM = instructions.SYSTEM_PROGRAM
local ASSOCIATED_TOKEN_PROGRAM = instructions.ASSOCIATED_TOKEN_PROGRAM
local MEMO_PROGRAM = instructions.MEMO_PROGRAM
local COMPUTE_BUDGET_PROGRAM = instructions.COMPUTE_BUDGET_PROGRAM

-- Every shape-rejection in this module is a `payment_invalid`: the on-chain
-- transaction failed one of the verifier's structural checks (mint, amount,
-- ATA, memo, fee payer, compute budget). The challenge itself already
-- verified upstream in `mpp.server.init.lua`. Network mismatches and
-- consume conflicts are tagged separately in `mpp.server.charge_handler`.
local function verifier_error(message)
  error({ code = error_codes.PAYMENT_INVALID, message = message })
end

local function is_native_sol(currency)
  return string.lower(currency or '') == 'sol'
end

local function account_key_at(tx, index)
  local key = tx.message.account_keys[index + 1]
  if key == nil then
    verifier_error('invalid account index ' .. tostring(index))
  end
  return key
end

local function amount_from(field, label)
  -- Rust models the wire amount as `String` (parsed to u64 downstream); a JSON
  -- numeric carrier is a schema mismatch the spine rejects, and accepting one
  -- in Lua would let a malformed challenge pass farther here than against
  -- the Rust reference. Reject anything that is not a non-empty digit string.
  if type(field) ~= 'string' or not field:match('^%d+$') then
    verifier_error(label .. ' must be an integer string')
  end
  return field
end

local function sum_splits(splits)
  local total = '0'
  for i = 1, #splits do
    total = uint.add(total, amount_from(splits[i].amount, 'split.amount'))
  end
  return total
end

local function expected_fee_payer(tx, method_details)
  if method_details.feePayer ~= true then
    return nil
  end
  local key = method_details.feePayerKey
  if type(key) ~= 'string' or key == '' then
    verifier_error('feePayer=true requires feePayerKey')
  end
  if tx.message.account_keys[1] ~= key then
    verifier_error('transaction fee payer mismatch')
  end
  return key
end

local function match_sol_transfer(tx, recipient, amount, fee_payer, matched)
  for index, ix in ipairs(tx.message.instructions) do
    if not matched[index]
      and instructions.program_id_for(tx, ix) == SYSTEM_PROGRAM
    then
      local parsed = instructions.parse_system_transfer(ix)
      if parsed and uint.compare(parsed.lamports, amount) == 0 then
        local source = account_key_at(tx, ix.accounts[1])
        local destination = account_key_at(tx, ix.accounts[2])
        if destination == recipient then
          if fee_payer and source == fee_payer then
            verifier_error('fee payer cannot fund the SOL payment transfer')
          end
          matched[index] = true
          return
        end
      end
    end
  end
  verifier_error('No matching SOL transfer of ' .. amount .. ' lamports to ' .. recipient)
end

local function match_spl_transfer(tx, recipient, mint, token_program, amount, decimals, fee_payer, matched)
  for index, ix in ipairs(tx.message.instructions) do
    if not matched[index] then
      local program = instructions.program_id_for(tx, ix)
      if (program == TOKEN_PROGRAM or program == TOKEN_2022_PROGRAM) and program == token_program then
        local parsed = instructions.parse_transfer_checked(ix)
        if parsed and uint.compare(parsed.amount, amount) == 0 then
          -- Rust types `methodDetails.decimals` as `Option<u8>`, so a string
          -- payload like `"6"` is a schema mismatch the spine rejects. Reject
          -- anything that is not nil or a plain number here so the same
          -- malformed challenge cannot settle against Lua either.
          if decimals ~= nil and type(decimals) ~= 'number' then
            verifier_error('methodDetails.decimals must be a number')
          end
          if decimals == nil or parsed.decimals == decimals then
            local mint_account = account_key_at(tx, ix.accounts[2])
            if mint_account == mint then
              local source_ata = account_key_at(tx, ix.accounts[1])
              local destination_ata = account_key_at(tx, ix.accounts[3])
              local authority = account_key_at(tx, ix.accounts[4])
              if fee_payer then
                if authority == fee_payer then
                  verifier_error('fee payer cannot authorize the SPL payment transfer')
                end
                local fee_payer_ata = ata.derive(fee_payer, mint, token_program)
                if source_ata == fee_payer_ata then
                  verifier_error('fee payer token account cannot fund the SPL payment transfer')
                end
              end
              local expected_ata = ata.derive(recipient, mint, token_program)
              if destination_ata == expected_ata then
                matched[index] = true
                return
              end
            end
          end
        end
      end
    end
  end
  verifier_error('No matching SPL transferChecked of ' .. amount .. ' to ' .. recipient)
end

local function verify_memos(tx, request, splits, matched)
  local memos = {}
  if request.externalId and request.externalId ~= '' then
    memos[#memos + 1] = { label = 'externalId', value = request.externalId }
  end
  for i = 1, #splits do
    if splits[i].memo and splits[i].memo ~= '' then
      memos[#memos + 1] = { label = 'split', value = splits[i].memo }
    end
  end
  for i = 1, #memos do
    local want = memos[i]
    if #want.value > 566 then
      verifier_error('memo cannot exceed 566 bytes')
    end
    local found = false
    for index, ix in ipairs(tx.message.instructions) do
      if not matched[index]
        and instructions.program_id_for(tx, ix) == MEMO_PROGRAM
        and ix.data == want.value
      then
        matched[index] = true
        found = true
        break
      end
    end
    if not found then
      verifier_error('No memo instruction found for ' .. want.label .. ' memo "' .. want.value .. '"')
    end
  end
end

local function validate_ata_create(tx, ix, expected_mint, allowed_owners, expected_token_program, expected_payer)
  if expected_mint == nil then
    verifier_error('ATA creation is not allowed for native SOL payments')
  end
  local parsed = instructions.parse_ata_create(ix)
  if parsed == nil then
    verifier_error('Unexpected ATA creation data')
  end
  if not parsed.idempotent then
    verifier_error('Only idempotent ATA creation is allowed')
  end
  if #ix.accounts ~= 6 then
    verifier_error('Unexpected ATA creation account layout')
  end
  local payer = account_key_at(tx, ix.accounts[1])
  local ata_address = account_key_at(tx, ix.accounts[2])
  local owner = account_key_at(tx, ix.accounts[3])
  local mint = account_key_at(tx, ix.accounts[4])
  local system_program = account_key_at(tx, ix.accounts[5])
  local token_program = account_key_at(tx, ix.accounts[6])
  if payer ~= expected_payer then
    verifier_error('ATA payer must match the transaction fee payer')
  end
  if mint ~= expected_mint then
    verifier_error('ATA creation mint does not match the charge currency')
  end
  local allowed = false
  for i = 1, #allowed_owners do
    if allowed_owners[i] == owner then
      allowed = true
      break
    end
  end
  if not allowed then
    verifier_error('ATA creation owner is not authorized by the challenge')
  end
  if system_program ~= SYSTEM_PROGRAM then
    verifier_error('ATA creation must reference the System Program')
  end
  if token_program ~= TOKEN_PROGRAM and token_program ~= TOKEN_2022_PROGRAM then
    verifier_error('ATA creation uses an unsupported token program')
  end
  if expected_token_program and token_program ~= expected_token_program then
    verifier_error('ATA creation token program does not match methodDetails.tokenProgram')
  end
  local expected_ata = ata.derive(owner, mint, token_program)
  if ata_address ~= expected_ata then
    verifier_error('ATA creation address does not match owner/mint/token program')
  end
  return owner
end

local function validate_allowlist(tx, matched, expected_mint, expected_token_program, fee_payer, splits)
  local created_owners = {}
  local required_owners = {}
  for i = 1, #splits do
    if splits[i].ataCreationRequired == true then
      required_owners[#required_owners + 1] = splits[i].recipient
    end
  end
  local allowed_owners
  if fee_payer then
    allowed_owners = required_owners
  else
    allowed_owners = {}
    for i = 1, #splits do
      allowed_owners[#allowed_owners + 1] = splits[i].recipient
    end
  end
  local expected_ata_payer = fee_payer or tx.message.account_keys[1]

  for index, ix in ipairs(tx.message.instructions) do
    local program = instructions.program_id_for(tx, ix)
    if program == COMPUTE_BUDGET_PROGRAM then
      instructions.parse_compute_budget(ix)
    elseif program == MEMO_PROGRAM
      or program == SYSTEM_PROGRAM
      or program == TOKEN_PROGRAM
      or program == TOKEN_2022_PROGRAM
    then
      if not matched[index] then
        verifier_error('Unexpected program instruction in payment transaction: ' .. program)
      end
    elseif program == ASSOCIATED_TOKEN_PROGRAM then
      local owner = validate_ata_create(tx, ix, expected_mint, allowed_owners, expected_token_program, expected_ata_payer)
      created_owners[owner] = true
    else
      verifier_error('Unexpected program instruction in payment transaction: ' .. program)
    end
  end

  for i = 1, #required_owners do
    if not created_owners[required_owners[i]] then
      verifier_error('Missing required ATA creation instruction for split recipient ' .. required_owners[i])
    end
  end
end

--- Verify a parsed transaction against a charge request. Raises on
--- mismatch; returns silently on success.
function M.verify_transaction(tx, request)
  if #tx.message.address_table_lookups > 0 then
    verifier_error('v0 address lookup tables are not supported')
  end
  local method_details = request.methodDetails or {}
  local splits = method_details.splits or {}
  if #splits > 8 then
    verifier_error('too many splits')
  end
  local total = amount_from(request.amount, 'request.amount')
  local split_total = sum_splits(splits)
  if uint.compare(total, split_total) <= 0 then
    verifier_error('split amounts exceed total amount')
  end
  local primary = uint.sub(total, split_total)
  if type(request.recipient) ~= 'string' or request.recipient == '' then
    verifier_error('recipient is required')
  end
  local fee_payer = expected_fee_payer(tx, method_details)
  local matched = {}

  if is_native_sol(request.currency) then
    for i = 1, #splits do
      if splits[i].ataCreationRequired == true then
        verifier_error('ataCreationRequired requires an SPL token charge')
      end
    end
    match_sol_transfer(tx, request.recipient, primary, fee_payer, matched)
    for i = 1, #splits do
      match_sol_transfer(tx, splits[i].recipient, amount_from(splits[i].amount, 'split.amount'), fee_payer, matched)
    end
    verify_memos(tx, request, splits, matched)
    validate_allowlist(tx, matched, nil, nil, fee_payer, splits)
  else
    local network = method_details.network or 'mainnet'
    local mint = protocol.resolve_mint(request.currency, network) or request.currency
    local token_program = method_details.tokenProgram or protocol.default_token_program_for_currency(request.currency, network)
    -- ataCreationRequired only makes sense when the challenge fixed an
    -- explicit mint, not when a symbol lookup expanded the currency to a
    -- mainnet default. Mirrors `ruby/lib/mpp/methods/solana/verifier.rb`
    -- (`mint != request.currency`): any symbol that protocol.resolve_mint
    -- rewrote into a different mint address has to be rejected here, not
    -- just the five hardcoded stablecoin symbols an earlier draft listed.
    for i = 1, #splits do
      if splits[i].ataCreationRequired == true and mint ~= request.currency then
        verifier_error('ataCreationRequired requires currency to be an SPL token mint address')
      end
    end
    match_spl_transfer(tx, request.recipient, mint, token_program, primary, method_details.decimals, fee_payer, matched)
    for i = 1, #splits do
      match_spl_transfer(tx, splits[i].recipient, mint, token_program,
        amount_from(splits[i].amount, 'split.amount'),
        method_details.decimals, fee_payer, matched)
    end
    verify_memos(tx, request, splits, matched)
    validate_allowlist(tx, matched, mint, token_program, fee_payer, splits)
  end
end

--- Verify a base64-encoded transaction payload against a charge request.
function M.verify_transaction_base64(transaction_base64, request)
  local tx = transaction.from_base64(transaction_base64)
  M.verify_transaction(tx, request)
end

--- Build a `transaction_verifier` callback suitable for
--- `mpp.server.charge_handler.new({transaction_verifier = ...})`.
function M.new_callback()
  return function(transaction_base64, request)
    M.verify_transaction_base64(transaction_base64, request)
  end
end

--- Build a `pull_blockhash_extractor` callback suitable for
--- `mpp.server.charge_handler.new({pull_blockhash_extractor = ...})`.
--- Returns the recent_blockhash base58 string so the handler's network
--- gate can run without re-parsing the transaction.
function M.new_blockhash_extractor()
  return function(transaction_base64)
    local tx = transaction.from_base64(transaction_base64)
    return tx.message.recent_blockhash
  end
end

return M
