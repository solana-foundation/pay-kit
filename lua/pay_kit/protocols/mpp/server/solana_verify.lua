local uint = require('pay_kit.util.uint')
local protocol = require('pay_kit.solana.mints')
local error_codes = require('pay_kit.protocol.core.error_codes')

local M = {}

-- Replay-store key prefix; must match the prefix used by init.lua's
-- _finalize_verification so the inner L8 consume and the outer
-- sanity-check guard hit the same namespace.
local CONSUMED_PREFIX_HOLDER = 'solana-charge:consumed:'

local TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
local TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
local SYSTEM_PROGRAM = '11111111111111111111111111111111'
local ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
local COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111'
local MEMO_PROGRAM = protocol.MEMO_PROGRAM
-- Compute budget caps mirror the Rust spine (server/charge.rs).
-- Caps exist so a malicious client cannot price-out a server's transactions.
local MAX_COMPUTE_UNIT_LIMIT = 200000
local MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5000000
local verify_sol_transfers
local verify_spl_transfers
local verify_memo_instructions
local verify_instruction_allowlist
local verify_compute_budget
local resolve_program

local function is_native_sol(currency)
  return string.lower(currency or '') == 'sol'
end

local function sum_split_amounts(splits)
  local total = '0'
  for _, split in ipairs(splits or {}) do
    total = uint.add(total, split.amount)
  end
  return total
end

local function primary_amount(amount, splits)
  local total_splits = sum_split_amounts(splits)
  if uint.compare(amount, total_splits) <= 0 then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'splits consume the entire amount')
  end
  return uint.sub(amount, total_splits)
end

local function build_expected_transfers(request)
  local splits = (request.methodDetails and request.methodDetails.splits) or {}
  local primary = primary_amount(request.amount, splits)
  local expected = {
    { recipient = request.recipient, amount = primary },
  }
  for _, split in ipairs(splits) do
    expected[#expected + 1] = {
      recipient = split.recipient,
      amount = split.amount,
    }
  end
  return expected
end

local function remove_at(list, index)
  table.remove(list, index)
end

local function normalize_program_id(ix)
  return ix.programId or ix.program_id or ''
end

local function normalize_program(ix)
  return ix.program or ''
end

local function parsed_program_id(ix)
  local program_id = normalize_program_id(ix)
  if program_id ~= '' then
    return program_id
  end
  if normalize_program(ix) == 'spl-memo' then
    return MEMO_PROGRAM
  end
  return ''
end

local function instruction_info(ix)
  return ix.parsed and ix.parsed.info or nil
end

local function parsed_memo_text(ix)
  if type(ix.parsed) == 'string' then
    return ix.parsed
  end
  local info = instruction_info(ix)
  if type(info) == 'table' then
    return info.memo or info.data
  end
  return nil
end

local function expected_memos(request, method_details)
  local expected = {}
  if request.externalId and request.externalId ~= '' then
    expected[#expected + 1] = {
      label = 'externalId',
      value = request.externalId,
    }
  end
  local splits = (request.methodDetails and request.methodDetails.splits) or method_details.splits or {}
  for _, split in ipairs(splits) do
    if split.memo and split.memo ~= '' then
      expected[#expected + 1] = {
        label = 'split',
        value = split.memo,
      }
    end
  end
  return expected
end

local function verify_confirmed_transaction(reference, tx, request, method_details, hooks)
  if not tx then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'transaction not found or not yet confirmed')
  end
  if tx.meta and tx.meta.err ~= nil then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'transaction failed on-chain')
  end

  local instructions = tx.transaction and tx.transaction.message and tx.transaction.message.instructions or {}
  if is_native_sol(request.currency) then
    verify_sol_transfers(instructions, request)
  else
    if not hooks.fetch_token_account then
      -- Callback contract violation: not a protocol rejection, so keep
      -- this as a developer-side error rather than a 402 surface.
      error('fetch_token_account callback is required for token verification')
    end
    verify_spl_transfers(instructions, request, method_details, hooks)
  end
  verify_memo_instructions(instructions, request, method_details)
  verify_compute_budget(instructions)
  verify_instruction_allowlist(instructions, request, method_details)

  return {
    reference = reference,
  }
end

function verify_sol_transfers(instructions, request)
  local expected = build_expected_transfers(request)
  local transfers = {}
  for _, ix in ipairs(instructions or {}) do
    if normalize_program(ix) == 'system' and ix.parsed and ix.parsed.type == 'transfer' then
      transfers[#transfers + 1] = ix
    end
  end
  for _, want in ipairs(expected) do
    local found = false
    for idx, ix in ipairs(transfers) do
      local info = instruction_info(ix)
      if info and info.destination == want.recipient and uint.compare(info.lamports, want.amount) == 0 then
        remove_at(transfers, idx)
        found = true
        break
      end
    end
    if not found then
      error_codes.raise(error_codes.PAYMENT_INVALID,
        'no matching SOL transfer for ' .. want.recipient)
    end
  end
end

function verify_spl_transfers(instructions, request, method_details, hooks)
  local expected = build_expected_transfers(request)
  local program_id = method_details.tokenProgram or protocol.default_token_program_for_currency(request.currency, method_details.network)
  local mint = protocol.resolve_mint(request.currency, method_details.network)
  if program_id ~= TOKEN_PROGRAM and program_id ~= TOKEN_2022_PROGRAM then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'unsupported token program: ' .. tostring(program_id))
  end
  local transfers = {}
  for _, ix in ipairs(instructions or {}) do
    if ix.parsed and ix.parsed.type == 'transferChecked' and normalize_program_id(ix) == program_id then
      transfers[#transfers + 1] = ix
    end
  end
  for _, want in ipairs(expected) do
    local found = false
    for idx, ix in ipairs(transfers) do
      local info = instruction_info(ix)
      if info and info.mint == mint and uint.compare(info.tokenAmount.amount, want.amount) == 0 then
        local account = hooks.fetch_token_account(info.destination)
        if account and account.owner == want.recipient and account.mint == mint then
          remove_at(transfers, idx)
          found = true
          break
        end
      end
    end
    if not found then
      error_codes.raise(error_codes.PAYMENT_INVALID,
        'no matching token transfer for ' .. want.recipient)
    end
  end
end

function verify_memo_instructions(instructions, request, method_details)
  local matched = {}
  for _, want in ipairs(expected_memos(request, method_details)) do
    if #want.value > 566 then
      error_codes.raise(error_codes.PAYMENT_INVALID, 'memo cannot exceed 566 bytes')
    end
    local found = false
    for index, ix in ipairs(instructions or {}) do
      if not matched[index] and parsed_program_id(ix) == MEMO_PROGRAM and parsed_memo_text(ix) == want.value then
        matched[index] = true
        found = true
        break
      end
    end
    if not found then
      error_codes.raise(error_codes.PAYMENT_INVALID,
        'No memo instruction found for ' .. want.label .. ' memo "' .. want.value .. '"')
    end
  end

  for index, ix in ipairs(instructions or {}) do
    if not matched[index] and parsed_program_id(ix) == MEMO_PROGRAM then
      error_codes.raise(error_codes.PAYMENT_INVALID,
        'unexpected Memo Program instruction in payment transaction')
    end
  end
end

-- Compute budget caps mirror the Rust spine. The instruction discriminator
-- byte 2 is SetComputeUnitLimit; byte 3 is SetComputeUnitPrice. Limits over
-- the caps are rejected pre-broadcast so a malicious client cannot bloat the
-- server's bill.
--
-- Branch order:
-- 1. If `parsed.type` or `info.units` / `info.microLamports` is present
--    (jsonParsed encoding), enforce caps against the parsed integer.
-- 2. If only `ix.data` is present, decode the discriminator and value from
--    raw bytes. base58 input is decoded via `Base58.decode_string` when the
--    server-side hook is available; otherwise the bytes are read directly.
-- 3. Compute-budget instructions we cannot classify fail closed; without a
--    discriminator we cannot prove the instruction stays under the cap.
function verify_compute_budget(instructions)
  for _, ix in ipairs(instructions or {}) do
    -- Use resolve_program (forward-declared above) so an instruction
    -- that ships only the `computeBudget` alias still passes through
    -- the cap. Standard jsonParsed adapters populate `programId`, but a
    -- third-party adapter that ships only the alias would otherwise
    -- skip the cap while still passing the allowlist downstream.
    if resolve_program(ix) == COMPUTE_BUDGET_PROGRAM then
      local parsed_type = ix.parsed and ix.parsed.type or nil
      local info = instruction_info(ix) or {}
      local handled = false
      if parsed_type == 'setComputeUnitLimit' or info.units ~= nil then
        local units = tonumber(info.units or info.computeUnits or 0) or 0
        if units > MAX_COMPUTE_UNIT_LIMIT then
          error('compute unit limit exceeds cap')
        end
        handled = true
      elseif parsed_type == 'setComputeUnitPrice' or info.microLamports ~= nil then
        local price = tonumber(info.microLamports or 0) or 0
        if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS then
          error('compute unit price exceeds cap')
        end
        handled = true
      elseif type(ix.data) == 'string' and #ix.data > 0 then
        -- Raw bytes path. Treat ix.data as Lua-native byte string and read
        -- discriminator + payload directly. The Solana JSON-RPC `binary`
        -- encoding gives us base58 strings; the harness adapters and live
        -- jsonParsed output never reach this branch, but a third-party
        -- adapter that bypasses jsonParsed must still hit the cap.
        local first = string.byte(ix.data, 1)
        if first == 2 and #ix.data >= 5 then
          local b1, b2, b3, b4 = string.byte(ix.data, 2, 5)
          local units = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
          if units > MAX_COMPUTE_UNIT_LIMIT then
            error('compute unit limit exceeds cap')
          end
          handled = true
        elseif first == 3 and #ix.data >= 9 then
          local b1, b2, b3, b4 = string.byte(ix.data, 2, 5)
          local b5, b6, b7, b8 = string.byte(ix.data, 6, 9)
          local low = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
          local high = b5 + b6 * 256 + b7 * 65536 + b8 * 16777216
          local price = low + high * 4294967296
          if price > MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS then
            error('compute unit price exceeds cap')
          end
          handled = true
        elseif first == 0 or first == 1 or first == 4 then
          -- Known non-cap discriminators (RequestUnits deprecated, RequestHeapFrame,
          -- SetLoadedAccountsDataSizeLimit). Accept; they do not affect compute caps.
          handled = true
        end
      end
      if not handled then
        -- Fail closed: a compute-budget instruction we cannot classify could
        -- be a SetComputeUnitLimit or SetComputeUnitPrice over the cap.
        error('compute budget instruction missing parsed type or raw payload')
      end
    end
  end
end

-- Reject any instruction whose program is not on the allowlist. Mirrors the
-- Rust spine (server/charge.rs validate_allowlist). Without this, a malicious
-- client could append arbitrary CPI calls to a payment transaction the server
-- is asked to broadcast (or fee-pay).
local PROGRAM_ALIAS = {
  system = SYSTEM_PROGRAM,
  ['spl-memo'] = MEMO_PROGRAM,
  ['spl-token'] = TOKEN_PROGRAM,
  ['spl-token-2022'] = TOKEN_2022_PROGRAM,
  ['spl-associated-token-account'] = ASSOCIATED_TOKEN_PROGRAM,
  ['compute-budget'] = COMPUTE_BUDGET_PROGRAM,
  computeBudget = COMPUTE_BUDGET_PROGRAM,
}

function resolve_program(ix)
  local program = normalize_program_id(ix)
  if program ~= '' then
    return program
  end
  local alias = normalize_program(ix)
  if PROGRAM_ALIAS[alias] then
    return PROGRAM_ALIAS[alias]
  end
  return ''
end

function verify_instruction_allowlist(instructions, request, method_details)
  local allowed = {
    [SYSTEM_PROGRAM] = true,
    [TOKEN_PROGRAM] = true,
    [TOKEN_2022_PROGRAM] = true,
    [ASSOCIATED_TOKEN_PROGRAM] = true,
    [MEMO_PROGRAM] = true,
    [COMPUTE_BUDGET_PROGRAM] = true,
  }
  -- SECURITY: when the charge advertises feePayer=true, methodDetails.feePayerKey
  -- is the authoritative server-side fee-payer pubkey (mirrors the rust spine
  -- ``expected_fee_payer`` invariant and the Python fix on PR #106
  -- 6925f4e + 5bf71d9). Any transfer-like instruction that sources lamports or
  -- tokens from this account must be rejected so the server cannot be coerced
  -- into co-signing a drain of fee-payer SOL or tokens. Without this guard a
  -- malicious client can append a SystemProgram::Transfer FROM the fee-payer
  -- on top of a valid SPL payment; the SPL verifier passes, the allowlist
  -- accepts SystemProgram, and the server co-signs the drain.
  local fee_payer_pubkey = nil
  if method_details and method_details.feePayer == true and method_details.feePayerKey
     and method_details.feePayerKey ~= '' then
    fee_payer_pubkey = method_details.feePayerKey
  end
  for _, ix in ipairs(instructions or {}) do
    local program = resolve_program(ix)
    if not allowed[program] then
      error('Unexpected program instruction in payment transaction: ' .. tostring(program))
    end
    if fee_payer_pubkey ~= nil then
      local info = instruction_info(ix)
      local parsed_type = ix.parsed and ix.parsed.type or nil
      if program == SYSTEM_PROGRAM and parsed_type == 'transfer'
         and info and info.source == fee_payer_pubkey then
        -- Mirrors rust ``verify_sol_transfer_instructions`` and Python
        -- ``_validate_instruction_allowlist`` 5bf71d9: reject any System
        -- transfer that sources lamports from the configured fee-payer.
        error('payment_invalid: fee payer cannot fund the SOL payment transfer')
      end
      if (program == TOKEN_PROGRAM or program == TOKEN_2022_PROGRAM)
         and parsed_type == 'transferChecked' and info then
        -- Mirrors rust ``verify_spl_transfer_instructions`` and Python
        -- ``_validate_instruction_allowlist`` 5bf71d9: reject any SPL
        -- transferChecked authorized by the fee-payer. (The source ATA owner
        -- check is performed in ``verify_spl_transfers`` via the token-account
        -- lookup hook; here we catch the authority shape directly so a
        -- fee-payer drain is rejected before the ATA fetch.)
        if info.authority == fee_payer_pubkey then
          error('payment_invalid: fee payer cannot authorize the SPL payment transfer')
        end
        if info.multisigAuthority == fee_payer_pubkey then
          error('payment_invalid: fee payer cannot authorize the SPL payment transfer')
        end
      end
    end
  end
end

function M.verify_signature(context, hooks)
  local payload = context.payload or {}
  local request = context.request or {}
  local method_details = context.method_details or request.methodDetails or {}

  if payload.signature == nil or payload.signature == '' then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'missing signature in credential payload')
  end

  -- B34: reject push-mode (type=signature) credentials when the challenge
  -- requires a server-side fee payer. A signature-only credential
  -- references an already-landed transaction that the client paid the fee
  -- for, defeating the server-funded charge. Reject before any RPC call
  -- so a partially-validated push credential never touches the network.
  -- Mirrors Rust spine and Ruby / PHP #100 / Python #106.
  if method_details.feePayer == true then
    error('Push-mode credentials are not allowed when the route uses a server-side fee payer')
  end

  if not hooks or type(hooks.fetch_transaction) ~= 'function' then
    -- Hooks contract violation: developer-side, not a 402 surface.
    error('fetch_transaction callback is required')
  end

  local tx = hooks.fetch_transaction(payload.signature)
  return verify_confirmed_transaction(payload.signature, tx, request, method_details, hooks)
end

function M.verify_transaction(context, hooks)
  local payload = context.payload or {}
  local request = context.request or {}
  local method_details = context.method_details or request.methodDetails or {}

  if payload.transaction == nil or payload.transaction == '' then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'missing transaction in credential payload')
  end
  -- Hooks contract violations stay developer-side; only protocol-level
  -- rejections carry an error code through the 402 surface.
  if not hooks or type(hooks.send_transaction) ~= 'function' then
    error('send_transaction callback is required')
  end
  if type(hooks.await_transaction) ~= 'function' then
    error('await_transaction callback is required')
  end

  -- SECURITY (PR #102 codex round 3 P1): the compute-budget cap and the
  -- instruction allowlist (including the fee-payer drain guard) MUST run
  -- BEFORE send_transaction. Previously these checks ran inside
  -- verify_confirmed_transaction (after broadcast + await), which let a
  -- malicious transaction be broadcast (and potentially settle on-chain)
  -- before the policy rejected it. The pre-broadcast checks operate on
  -- jsonParsed-style instructions supplied by `hooks.parse_transaction`;
  -- the caller is responsible for decoding the wire bytes into the same
  -- shape Solana's getTransaction(jsonParsed) returns. If the hook is
  -- missing we fail closed so the security invariant cannot be silently
  -- lost on integration.
  if type(hooks.parse_transaction) ~= 'function' then
    error('parse_transaction callback is required for pull-mode pre-broadcast policy checks')
  end
  local parsed = hooks.parse_transaction(payload.transaction)
  if type(parsed) ~= 'table' then
    error('parse_transaction must return a parsed transaction table')
  end
  -- Accept three shapes for ergonomic adapter authoring:
  --   { instructions = {...} }
  --   { message = { instructions = {...} } }       (Solana message shape)
  --   { transaction = { message = { instructions = {...} } } }  (jsonParsed wrapper)
  local pre_instructions = parsed.instructions
  if pre_instructions == nil and parsed.message then
    pre_instructions = parsed.message.instructions
  end
  if pre_instructions == nil and parsed.transaction and parsed.transaction.message then
    pre_instructions = parsed.transaction.message.instructions
  end
  if type(pre_instructions) ~= 'table' then
    error('parse_transaction result is missing message.instructions')
  end
  -- Pre-broadcast: compute-budget cap + instruction allowlist (incl.
  -- fee-payer drain guard). Reject BEFORE any RPC call.
  verify_compute_budget(pre_instructions)
  verify_instruction_allowlist(pre_instructions, request, method_details)

  local signature = hooks.send_transaction(payload.transaction)
  if signature == nil or signature == '' then
    error_codes.raise(error_codes.PAYMENT_INVALID, 'send_transaction returned an empty signature')
  end
  -- L8 broadcast-then-consume-then-await ordering. Mirrors the Rust /
  -- Ruby / PHP / Python spine: the durable replay marker MUST be
  -- written between send_transaction and await_transaction. If we await
  -- first and the await times out, a retry can re-broadcast the same
  -- bytes, leak through the not-yet-marked store, and double-pay.
  -- Consuming the signature before await closes that window: a retry
  -- after timeout hits the already-consumed marker and short-circuits.
  local replay_key = CONSUMED_PREFIX_HOLDER .. signature
  local stored = false
  if context.store ~= nil and type(context.store.put_if_absent) == 'function' then
    local inserted = context.store:put_if_absent(replay_key, true)
    if not inserted then
      error('payment already consumed')
    end
    stored = true
  end
  local tx = hooks.await_transaction(signature)
  -- Post-confirmation: verify the on-chain artifact shape (recipient
  -- ATA owner, mint, amount, memos). Compute-budget + allowlist checks
  -- also re-run here as defense-in-depth against an RPC that returns
  -- different instructions than what the client supplied pre-broadcast.
  local result = verify_confirmed_transaction(signature, tx, request, method_details, hooks)
  if stored then
    -- Signal to the server caller (init.lua _finalize_verification) that
    -- the replay marker is already durable, so the outer put_if_absent
    -- becomes a no-op and does not double-consume. When `context.store`
    -- was nil we did NOT write the marker, so leave `consumed` unset so
    -- the outer guard runs against its own store and replay protection
    -- stays intact (mirrors codex round 3 P2 on the silent-disable gap).
    result.replay_key = replay_key
    result.consumed = true
  end
  return result
end

function M.new_signature_verifier(hooks)
  return function(context)
    if context.payload.type == 'transaction' then
      return M.verify_transaction(context, hooks)
    end
    return M.verify_signature(context, hooks)
  end
end

--- Build a real (non-hooks) verifier that decodes the wire transaction
--- through the Lua Solana codec landed in this PR. Mirrors what the Ruby
--- and Rust spines do: parse the credential's base64 transaction, walk
--- every instruction, and reject on a single failed assertion.
---
--- @param opts table (optional)
---   pull_signer       optional Signer for the cosign path. When set, the
---                     returned verifier exposes a `cosign(base64)`
---                     companion the charge handler wires as
---                     `pull_transaction_signer`.
---
--- The returned table carries:
---   transaction_verifier    function(base64, request) -> ok | raises
---   pull_blockhash_extractor function(base64) -> blockhash_b58
---   pull_transaction_signer  function(base64) -> signed_b64 (when opts.pull_signer set)
function M.new_real_verifier(opts)
  opts = opts or {}
  local real = require('pay_kit.solana.verifier')
  local out = {
    transaction_verifier = real.new_callback(),
    pull_blockhash_extractor = real.new_blockhash_extractor(),
  }
  if opts.pull_signer then
    out.pull_transaction_signer = function(transaction_base64)
      return opts.pull_signer:cosign_base64(transaction_base64)
    end
  end
  return out
end

return M
