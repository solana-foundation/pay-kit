--[[
Per-program Solana instruction parsers.

Each parser inspects the raw instruction `data` bytes and returns a
typed table the verifier can match against the challenge request:

  - SPL Token + Token-2022 transferChecked (discriminator 12)
  - System Program transfer              (discriminator 2)
  - Memo Program v1 + v2                 (free-form bytes)
  - Associated Token Program             (create + create-idempotent)
  - Compute Budget                       (SetComputeUnitLimit / Price)

Amounts come back as decimal strings so they can be compared with
`mpp.util.uint.compare` without forcing the caller through Lua's
double-precision number type (which only carries 53 significant bits
and would silently truncate large u64 lamport values).
]]

local uint = require('mpp.util.uint')

local M = {}

local TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
local TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
local SYSTEM_PROGRAM = '11111111111111111111111111111111'
local ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
local MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
local COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111'

-- Audit-v2 caps shared with the Rust spine and the Ruby verifier.
local MAX_COMPUTE_UNIT_LIMIT = 200000
local MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5000000

M.TOKEN_PROGRAM = TOKEN_PROGRAM
M.TOKEN_2022_PROGRAM = TOKEN_2022_PROGRAM
M.SYSTEM_PROGRAM = SYSTEM_PROGRAM
M.ASSOCIATED_TOKEN_PROGRAM = ASSOCIATED_TOKEN_PROGRAM
M.MEMO_PROGRAM = MEMO_PROGRAM
M.COMPUTE_BUDGET_PROGRAM = COMPUTE_BUDGET_PROGRAM
M.MAX_COMPUTE_UNIT_LIMIT = MAX_COMPUTE_UNIT_LIMIT
M.MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS

-- Decode a little-endian unsigned integer in the byte range [start, start+len).
-- Returns a decimal string so values above 2^53 stay exact through the
-- verifier's uint comparisons.
local function decode_le_uint(data, start, length)
  -- Build the value from the most-significant byte down. Multiplying a
  -- decimal-string accumulator by 256 keeps the result exact.
  -- Use a small helper that operates on a digit array for efficiency
  -- because LuaJIT cannot inline string concatenation in a tight loop.
  local digits = { 0 }
  for i = length - 1, 0, -1 do
    local byte = data:byte(start + i)
    if byte == nil then
      error('instruction data shorter than expected: needed ' .. length .. ' bytes from ' .. start)
    end
    local carry = byte
    for j = 1, #digits do
      local value = digits[j] * 256 + carry
      digits[j] = value % 10
      carry = math.floor(value / 10)
    end
    while carry > 0 do
      digits[#digits + 1] = carry % 10
      carry = math.floor(carry / 10)
    end
  end
  -- Walk the array MSD-first into a string.
  while #digits > 1 and digits[#digits] == 0 do
    digits[#digits] = nil
  end
  local chars = {}
  for i = #digits, 1, -1 do
    chars[#chars + 1] = tostring(digits[i])
  end
  return table.concat(chars)
end

M.decode_le_uint = decode_le_uint

--- Parse an SPL Token / Token-2022 transferChecked instruction.
-- Returns nil if the instruction's data does not match the transferChecked
-- shape so the caller can keep iterating.
function M.parse_transfer_checked(ix)
  local data = ix.data
  if #data < 10 then
    return nil
  end
  if data:byte(1) ~= 12 then
    return nil
  end
  return {
    kind = 'spl_transfer_checked',
    amount = decode_le_uint(data, 2, 8),
    decimals = data:byte(10),
    accounts = ix.accounts,
  }
end

--- Parse a System Program transfer instruction.
function M.parse_system_transfer(ix)
  local data = ix.data
  if #data < 12 then
    return nil
  end
  -- First four bytes are the SystemProgram discriminator (little-endian u32).
  if data:byte(1) ~= 2 or data:byte(2) ~= 0 or data:byte(3) ~= 0 or data:byte(4) ~= 0 then
    return nil
  end
  return {
    kind = 'system_transfer',
    lamports = decode_le_uint(data, 5, 8),
    accounts = ix.accounts,
  }
end

--- Parse a Memo Program instruction (v1 and v2 share the same data shape:
--- the entire `data` field is the memo bytes).
function M.parse_memo(ix)
  return {
    kind = 'memo',
    memo = ix.data,
  }
end

--- Parse an Associated Token Account creation instruction. The on-chain
--- program treats an empty `data` field (or a single 0x00 byte for explicit
--- create) as create, and a 0x01 byte as create-idempotent.
function M.parse_ata_create(ix)
  local data = ix.data or ''
  local idempotent
  if data == '' or data == string.char(0) then
    idempotent = false
  elseif data == string.char(1) then
    idempotent = true
  else
    return nil
  end
  return {
    kind = 'ata_create',
    idempotent = idempotent,
    accounts = ix.accounts,
  }
end

--- Parse a Compute Budget instruction.
--- Returns the typed table or raises with the canonical cap-violation
--- message so the verifier short-circuits without an extra branch.
function M.parse_compute_budget(ix)
  local data = ix.data or ''
  if #data < 1 then
    error('Unsupported compute budget instruction')
  end
  if #ix.accounts > 0 then
    error('Compute budget instruction must not have accounts')
  end
  local discriminator = data:byte(1)
  if discriminator == 2 then
    if #data ~= 5 then
      error('Unsupported compute budget instruction')
    end
    -- Compare decimal strings via mpp.util.uint so u32 / u64 values above
    -- 2^53 (Lua double mantissa boundary) still compare exactly. The u32
    -- compute-unit-limit field never exceeds 2^32 so the precision risk is
    -- nil here, but keeping the comparison string-based aligns with the
    -- u64 price path below and survives a future cap raise without a
    -- silent precision drop.
    local limit_str = decode_le_uint(data, 2, 4)
    if uint.compare(limit_str, tostring(MAX_COMPUTE_UNIT_LIMIT)) > 0 then
      error('Compute unit limit ' .. limit_str .. ' exceeds maximum ' .. MAX_COMPUTE_UNIT_LIMIT)
    end
    return { kind = 'compute_budget_set_limit', limit = limit_str }
  end
  if discriminator == 3 then
    if #data ~= 9 then
      error('Unsupported compute budget instruction')
    end
    -- u64 price values above 2^53 cannot be compared safely via tonumber:
    -- Lua doubles only carry 53 significant bits, so the cast collapses
    -- distinct u64 values to the same float and the cap check would fire
    -- on the wrong side of the boundary. Compare the exact decimal strings
    -- through mpp.util.uint so a future cap raise above 2^53 still rejects
    -- genuinely over-cap transactions.
    local price_str = decode_le_uint(data, 2, 8)
    if uint.compare(price_str, tostring(MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS)) > 0 then
      error('Compute unit price ' .. price_str .. ' exceeds maximum ' .. MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS)
    end
    return { kind = 'compute_budget_set_price', price = price_str }
  end
  -- Known non-cap discriminators that do not affect compute-budget caps:
  --   0 = RequestUnits (deprecated)
  --   1 = RequestHeapFrame
  --   4 = SetLoadedAccountsDataSizeLimit
  -- The hooks-based verifier path in `mpp.server.solana_verify` accepts
  -- these as harmless pass-through, so the real verifier path must
  -- behave identically to avoid a behavioral split where a transaction
  -- whose wallet inserts disc 1 or 4 verifies under hooks but is
  -- rejected by the real verifier with `payment_invalid`.
  if discriminator == 0 or discriminator == 1 or discriminator == 4 then
    return { kind = 'compute_budget_noop', discriminator = discriminator }
  end
  error('Unsupported compute budget instruction')
end

--- Resolve the program-id base58 string for an instruction in a parsed
--- transaction. Bridges the codec (which stores account-key strings) with
--- the per-program parsers (which key off the resolved program id).
function M.program_id_for(tx, ix)
  local index = ix.program_id_index + 1
  local key = tx.message.account_keys[index]
  if key == nil then
    error('invalid program id index ' .. tostring(ix.program_id_index))
  end
  return key
end

return M
