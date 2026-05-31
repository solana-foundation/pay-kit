--[[
Regression coverage for x402 exact-scheme parity with the Rust spine
(rust/crates/x402/src/protocol/schemes/exact/verify.rs).

Each test asserts the rust-matching behaviour and would have FAILED on
the pre-fix Lua verifier:

  * compute-unit-price cap raised from 50_000 to 5_000_000 (verify.rs:17)
  * transfer program bound to the canonical TOKEN/TOKEN_2022 set, NOT to
    `extra.tokenProgram` (verify.rs:373)
  * u64 amount decoded exactly (verify.rs:405-409) so a high-range value
    cannot collide with a different amount through float rounding
]]

local helper = require('tests.test_helper')
local base64 = require('pay_kit.util.base64_std')
local base58 = require('pay_kit.solana.base58')
local tx_mod = require('pay_kit.solana.transaction')
local ata    = require('pay_kit.solana.ata')
local x402_verify = require('pay_kit.protocols.x402.exact.verify')

local COMPUTE_BUDGET = 'ComputeBudget111111111111111111111111111111'
local MEMO_PROGRAM   = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'
local TOKEN_PROGRAM  = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
local TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'

-- Exact little-endian u32 (full range).
local function u32_le(n)
  local out = {}
  for _ = 1, 4 do out[#out + 1] = string.char(n % 256); n = math.floor(n / 256) end
  return table.concat(out)
end

-- Exact little-endian u64 from a decimal STRING so the full u64 range is
-- representable without float rounding (the prior numeric helpers in the
-- other specs top out at 2^53).
local function u64_le_from_decimal(decimal)
  -- Repeated divmod by 256 over an arbitrary-precision decimal string.
  local digits = decimal
  local out = {}
  for _ = 1, 8 do
    local quotient, carry = {}, 0
    for i = 1, #digits do
      local cur = carry * 10 + tonumber(digits:sub(i, i))
      quotient[#quotient + 1] = tostring(math.floor(cur / 256))
      carry = cur % 256
    end
    local remainder = carry
    out[#out + 1] = string.char(remainder)
    digits = table.concat(quotient):gsub('^0+', '')
    if digits == '' then digits = '0' end
  end
  return table.concat(out)
end

local function build_ix(program_index, accounts, data)
  local out = {string.char(program_index), tx_mod.compact_u16(#accounts)}
  for i = 1, #accounts do out[#out + 1] = string.char(accounts[i]) end
  out[#out + 1] = tx_mod.compact_u16(#data)
  out[#out + 1] = data
  return table.concat(out)
end

-- Standard 8-key layout. token_program controls which SPL program id the
-- transfer instruction points at (slot index 6).
local function standard_keys(facilitator, source, mint, destination, authority, token_program)
  return table.concat({
    base58.decode(facilitator),
    base58.decode(source),
    base58.decode(mint),
    base58.decode(destination),
    base58.decode(authority),
    base58.decode(COMPUTE_BUDGET),
    base58.decode(token_program),
    base58.decode(MEMO_PROGRAM),
  })
end

local function assemble(account_keys_blob, account_count, instruction_blobs)
  local header = string.char(1, 0, 3)
  local recent_blockhash = string.rep('\0', 32)
  local ix_blob = tx_mod.compact_u16(#instruction_blobs)
  for _, ix in ipairs(instruction_blobs) do ix_blob = ix_blob .. ix end
  local lookups = tx_mod.compact_u16(0)
  local message = '\x80' .. header .. tx_mod.compact_u16(account_count) ..
                  account_keys_blob .. recent_blockhash .. ix_blob .. lookups
  local sigs = tx_mod.compact_u16(1) .. string.rep('\0', 64)
  return sigs .. message
end

local function actors()
  return base58.encode(string.rep('\1', 32)),  -- facilitator
         base58.encode(string.rep('\2', 32)),  -- authority
         base58.encode(string.rep('\3', 32)),  -- source
         base58.encode(string.rep('\4', 32)),  -- mint
         base58.encode(string.rep('\5', 32))   -- pay_to
end

-- Build a full transaction whose transfer carries the given decimal amount
-- and token program; price_micro sets the compute-unit-price value.
local function make_tx(opts)
  local facilitator, authority, source, mint, pay_to = actors()
  local token_program = opts.token_program or TOKEN_PROGRAM
  local destination = ata.derive(pay_to, mint, token_program)
  local keys = standard_keys(facilitator, source, mint, destination, authority, token_program)
  local raw = assemble(keys, 8, {
    build_ix(5, {}, string.char(2) .. u32_le(200000)),
    build_ix(5, {}, string.char(3) .. u64_le_from_decimal(opts.price_micro or '1000')),
    build_ix(6, {1, 2, 3, 4},
             string.char(12) .. u64_le_from_decimal(opts.amount or '1000') .. string.char(6)),
    build_ix(7, {}, '/paid'),
  })
  return raw, facilitator, mint, pay_to
end

local function offer(facilitator, mint, pay_to, opts)
  opts = opts or {}
  local extra = {feePayer = facilitator, decimals = 6, memo = '/paid'}
  if opts.token_program ~= nil then extra.tokenProgram = opts.token_program end
  return {
    scheme = 'exact', network = 'solana:dev',
    asset = mint, amount = opts.amount or '1000', payTo = pay_to,
    extra = extra,
  }
end

-- #39: compute-unit price between the old 50_000 cap and the rust 5_000_000
-- cap must now be ACCEPTED (was rejected pre-fix as compute_price_too_high).
helper.test('parity: compute-unit price above old 50k cap but under 5M is accepted', function()
  local raw, facilitator, mint, pay_to = make_tx({price_micro = '60000'})
  local ok = pcall(x402_verify.verify, base64.encode(raw),
    offer(facilitator, mint, pay_to, {token_program = TOKEN_PROGRAM}), {facilitator})
  helper.assert_true(ok, 'price 60000 must pass under the 5M rust cap')
end)

helper.test('parity: compute-unit price above the 5M rust cap is rejected', function()
  local raw, facilitator, mint, pay_to = make_tx({price_micro = '5000001'})
  local ok, err = pcall(x402_verify.verify, base64.encode(raw),
    offer(facilitator, mint, pay_to, {token_program = TOKEN_PROGRAM}), {facilitator})
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('compute_price', 1, true) ~= nil, tostring(err))
end)

-- #42: an offer that OMITS extra.tokenProgram must still verify against a
-- canonical TOKEN_PROGRAM transfer (rust binds to the program set, not to
-- extra.tokenProgram). Pre-fix this raised missing_extra_tokenProgram.
helper.test('parity: offer without extra.tokenProgram still verifies TOKEN_PROGRAM transfer', function()
  local raw, facilitator, mint, pay_to = make_tx({token_program = TOKEN_PROGRAM})
  local ok, err = pcall(x402_verify.verify, base64.encode(raw),
    offer(facilitator, mint, pay_to), {facilitator})
  helper.assert_true(ok, 'expected accept; got: ' .. tostring(err))
end)

-- #42: Token-2022 transfer is accepted by the canonical program set even
-- when the offer omits extra.tokenProgram.
helper.test('parity: Token-2022 transfer accepted without extra.tokenProgram', function()
  local raw, facilitator, mint, pay_to = make_tx({token_program = TOKEN_2022_PROGRAM})
  local ok, err = pcall(x402_verify.verify, base64.encode(raw),
    offer(facilitator, mint, pay_to), {facilitator})
  helper.assert_true(ok, 'expected accept; got: ' .. tostring(err))
end)

-- #43: high-range u64 amount is compared EXACTLY. 9007199254740993 = 2^53+1
-- which float math rounds to 2^53; the exact decoder must accept the true
-- value and reject the rounded neighbour.
helper.test('parity: high-range u64 amount above 2^53 matches exactly', function()
  local big = '9007199254740993'  -- 2^53 + 1
  local raw, facilitator, mint, pay_to = make_tx({amount = big})
  local ok, err = pcall(x402_verify.verify, base64.encode(raw),
    offer(facilitator, mint, pay_to, {token_program = TOKEN_PROGRAM, amount = big}), {facilitator})
  helper.assert_true(ok, 'exact 2^53+1 amount must match; got: ' .. tostring(err))
end)

helper.test('parity: u64 amount off-by-one above 2^53 is rejected', function()
  local raw, facilitator, mint, pay_to = make_tx({amount = '9007199254740993'})  -- 2^53+1
  -- Offer expects 2^53 (the value a lossy float decode would collapse to).
  local ok, err = pcall(x402_verify.verify, base64.encode(raw),
    offer(facilitator, mint, pay_to,
          {token_program = TOKEN_PROGRAM, amount = '9007199254740992'}), {facilitator})
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('amount_mismatch', 1, true) ~= nil, tostring(err))
end)
