--[[
Associated Token Account derivation.

Solana's `find_program_address` walks bump bytes from 255 down to 0,
hashing the seeds plus the candidate bump plus the program id plus the
canonical "ProgramDerivedAddress" suffix with SHA-256, and accepting
the first candidate that is *not* a point on the Ed25519 curve. Solana
uses the pure curve-equation check, not libsodium's
`crypto_core_ed25519_is_valid_point` (which additionally rejects points
in the small Ed25519 subgroup). The two semantics differ for a small
fraction of candidates, and the Solana-side rule is the canonical one
because the on-chain program at
`solana-program-library/associated-token-account` uses it verbatim.

This module ports the Ruby reference's modular-arithmetic on-curve
check at `ruby/lib/mpp/methods/solana/public_key.rb:47-73` into a
minimal in-file bignum helper. Lua does not ship arbitrary-precision
arithmetic; the helper operates on base-2^24 digit arrays and only
exposes the three operations the on-curve check needs: modular
multiply, modular inverse via Fermat's little theorem, and Tonelli /
sqrt over the Edwards prime.
]]

local base58 = require('mpp.util.base58')
local crypto = require('mpp.util.crypto')

local M = {}

local PROGRAM_DERIVED_ADDRESS_SEED = 'ProgramDerivedAddress'

-- Minimal little-endian base-2^24 bignum just for the on-curve test. The
-- Ed25519 prime p = 2^255 - 19 fits in 11 base-2^24 digits; intermediate
-- products fit in 22 digits. We work modulo p throughout so the bignum
-- never grows past 22 digits before normalization.
local BASE = 16777216 -- 2^24
local BIGINT_DIGITS = 32 -- room for 22 + headroom

local P = {} -- 2^255 - 19 as base-2^24 little-endian digits
do
  -- Compute 2^255 - 19 step by step.
  local digits = {}
  for i = 1, BIGINT_DIGITS do digits[i] = 0 end
  -- 2^255 = 1 shifted to bit 255. 255 / 24 = 10 remainder 15; that's
  -- digit index 11 (1-based) with value 2^15.
  digits[11] = 32768 -- 2^15
  -- Subtract 19 with borrow handling.
  local borrow = 19
  for i = 1, BIGINT_DIGITS do
    local value = digits[i] - borrow
    if value < 0 then
      value = value + BASE
      borrow = 1
    else
      borrow = 0
    end
    P[i] = value
    if borrow == 0 then break end
  end
  for i = #P + 1, BIGINT_DIGITS do P[i] = 0 end
end

local function bigint_zero()
  local d = {}
  for i = 1, BIGINT_DIGITS do d[i] = 0 end
  return d
end

local function bigint_from_bytes(bytes)
  -- Bytes are little-endian (Ed25519 convention); pack 3 bytes -> 1 digit.
  local d = bigint_zero()
  local len = #bytes
  for i = 0, len - 1 do
    local digit_index = math.floor(i / 3) + 1
    local within = (i % 3) * 8
    d[digit_index] = d[digit_index] + bytes:byte(i + 1) * (2 ^ within)
  end
  return d
end

local function bigint_copy(src)
  local d = bigint_zero()
  for i = 1, BIGINT_DIGITS do d[i] = src[i] end
  return d
end

local function bigint_cmp(a, b)
  for i = BIGINT_DIGITS, 1, -1 do
    if a[i] > b[i] then return 1 end
    if a[i] < b[i] then return -1 end
  end
  return 0
end

local function bigint_sub_in_place(a, b)
  -- a := a - b, both little-endian. Assumes a >= b.
  local borrow = 0
  for i = 1, BIGINT_DIGITS do
    local value = a[i] - b[i] - borrow
    if value < 0 then
      value = value + BASE
      borrow = 1
    else
      borrow = 0
    end
    a[i] = value
  end
end

local function bigint_add_in_place(a, b)
  local carry = 0
  for i = 1, BIGINT_DIGITS do
    local value = a[i] + b[i] + carry
    if value >= BASE then
      value = value - BASE
      carry = 1
    else
      carry = 0
    end
    a[i] = value
  end
end

local function mod_reduce(a)
  -- Reduce a modulo p in place. Repeated subtractions are enough because
  -- the largest intermediate value we feed in is < p * 2^24 (a product of
  -- two p-sized values), so a multiplication is followed by enough
  -- subtractions to bring the value back below p.
  while bigint_cmp(a, P) >= 0 do
    bigint_sub_in_place(a, P)
  end
  return a
end

local function bigint_mul_mod(a, b)
  -- Long multiply followed by mod reduction. Intermediate stays in a wider
  -- accumulator (Lua doubles have 53 bits; each product is at most 2^48 so
  -- two summed products still fit before we propagate the carry).
  local out = bigint_zero()
  for i = 1, BIGINT_DIGITS do
    local carry = 0
    for j = 1, BIGINT_DIGITS - i + 1 do
      local idx = i + j - 1
      local value = out[idx] + a[i] * b[j] + carry
      out[idx] = value % BASE
      carry = math.floor(value / BASE)
    end
  end
  -- Now reduce. With Ed25519 prime p, 2^255 ≡ 19 (mod p). Fold high digits.
  -- Each digit beyond index 11 contributes value * 2^((idx-1)*24); when
  -- multiplied by 19 we get the equivalent low-digit contribution. Run two
  -- folding passes to bring everything below 2^256, then reduce by P.
  for _ = 1, 2 do
    local extra = bigint_zero()
    -- Bit 255 lies inside digit 11 at bit 15. Any bit at or above 255 is
    -- folded with a factor of 19.
    -- Take the bits from digit 11 above bit 15 and from digits 12..end.
    local high_in_11 = math.floor(out[11] / 32768)
    out[11] = out[11] % 32768
    extra[1] = high_in_11 * 19
    for i = 12, BIGINT_DIGITS do
      local v = out[i]
      out[i] = 0
      if v ~= 0 then
        -- v occupies bits (i-1)*24..i*24-1. Multiplying by 19 and shifting
        -- by (-(255 - (i-1)*24)) bits is equivalent to adding v * 19 * 2^((i-1)*24 - 255)
        -- but we work in digits, so this folds to digit ((i-1)*24 - 255)/24
        -- plus residual bits. Easier: convert v back to a digit-shift.
        local shift_bits = (i - 1) * 24 - 255
        local shift_digits = math.floor(shift_bits / 24)
        local shift_within = shift_bits % 24
        local low = (v * 19) % (2 ^ (24 - shift_within))
        local high = math.floor(v * 19 / (2 ^ (24 - shift_within)))
        extra[1 + shift_digits] = extra[1 + shift_digits] + low * (2 ^ shift_within)
        extra[2 + shift_digits] = extra[2 + shift_digits] + high
      end
    end
    -- Normalize extra so each digit is below BASE.
    local carry = 0
    for i = 1, BIGINT_DIGITS do
      local v = extra[i] + carry
      extra[i] = v % BASE
      carry = math.floor(v / BASE)
    end
    bigint_add_in_place(out, extra)
    -- Normalize out as well.
    carry = 0
    for i = 1, BIGINT_DIGITS do
      local v = out[i] + carry
      out[i] = v % BASE
      carry = math.floor(v / BASE)
    end
  end
  return mod_reduce(out)
end

local function bigint_from_small(n)
  local d = bigint_zero()
  d[1] = n
  return d
end

local function bigint_is_zero(a)
  for i = 1, BIGINT_DIGITS do
    if a[i] ~= 0 then return false end
  end
  return true
end

local function bigint_sub_mod(a, b)
  -- (a - b) mod p
  local d = bigint_copy(a)
  if bigint_cmp(d, b) < 0 then
    bigint_add_in_place(d, P)
  end
  bigint_sub_in_place(d, b)
  return mod_reduce(d)
end

local function bigint_pow_mod(base, exponent)
  -- Binary exponentiation. `exponent` is a base-2^24 digit array.
  local result = bigint_from_small(1)
  local base_copy = bigint_copy(base)
  for i = 1, BIGINT_DIGITS do
    local digit = exponent[i]
    if digit == 0 and i > 1 then
      -- Skip the inner bit loop only after we've passed the top bit.
      local rest_zero = true
      for j = i + 1, BIGINT_DIGITS do
        if exponent[j] ~= 0 then rest_zero = false break end
      end
      if rest_zero then break end
    end
    for _ = 1, 24 do
      if digit % 2 == 1 then
        result = bigint_mul_mod(result, base_copy)
      end
      digit = math.floor(digit / 2)
      base_copy = bigint_mul_mod(base_copy, base_copy)
    end
  end
  return result
end

local function bigint_inv_mod(a)
  -- Fermat: a^(p-2) mod p.
  local exponent = bigint_copy(P)
  -- Subtract 2.
  exponent[1] = exponent[1] - 2
  return bigint_pow_mod(a, exponent)
end

-- Ed25519 curve constant d ≡ -121665 / 121666 (mod p).
local D
do
  local num = bigint_sub_mod(bigint_from_small(0), bigint_from_small(121665))
  local denom_inv = bigint_inv_mod(bigint_from_small(121666))
  D = bigint_mul_mod(num, denom_inv)
end

-- The curve equation: -x^2 + y^2 = 1 + d*x^2*y^2. Solving for x^2:
--   x^2 = (y^2 - 1) / (1 + d*y^2)
-- A candidate is on the curve iff x^2 has a square root mod p.
local function is_on_curve(bytes)
  if #bytes ~= 32 then
    error('on-curve check requires exactly 32 bytes')
  end
  -- Solana encodes the candidate as little-endian bytes; the high bit of
  -- the last byte is the sign bit of x. For the on-curve check we only
  -- need the y coordinate, so mask the high bit.
  local masked = bytes:sub(1, 31) .. string.char(bytes:byte(32) % 128)
  local y = bigint_from_bytes(masked)
  local y2 = bigint_mul_mod(y, y)
  local u = bigint_sub_mod(y2, bigint_from_small(1))
  local v = bigint_copy(bigint_mul_mod(D, y2))
  bigint_add_in_place(v, bigint_from_small(1))
  mod_reduce(v)
  if bigint_is_zero(v) then
    return false
  end
  local x2 = bigint_mul_mod(u, bigint_inv_mod(v))
  -- p = 2^255 - 19, so (p+3)/8 lets us compute a tentative sqrt via x2^((p+3)/8).
  -- Build the exponent in place: copy P, add 3 (p is congruent to 5 mod 8 so
  -- p+3 is divisible by 8), then divide by 8.
  --
  -- A bignum right-shift must iterate MSB-to-LSB so each digit's high bits
  -- become the low bits of the digit below it. An earlier draft of this
  -- module had a forward-direction loop here that lost bits in the wrong
  -- direction; the canonical reverse loop below is the only one that runs.
  local exponent_a = bigint_copy(P)
  exponent_a[1] = exponent_a[1] + 3
  -- Carry-normalize first so each digit fits in BASE before the shift.
  local carry = 0
  for i = 1, BIGINT_DIGITS do
    local v_norm = exponent_a[i] + carry
    exponent_a[i] = v_norm % BASE
    carry = math.floor(v_norm / BASE)
  end
  local borrow_bits = 0
  for i = BIGINT_DIGITS, 1, -1 do
    local val = exponent_a[i] + borrow_bits * BASE
    exponent_a[i] = math.floor(val / 8)
    borrow_bits = val % 8
  end
  local root = bigint_pow_mod(x2, exponent_a)
  local root_sq = bigint_mul_mod(root, root)
  if bigint_cmp(root_sq, x2) == 0 then
    return true
  end
  -- Try root * 2^((p-1)/4): this multiplies by a square root of -1.
  local exponent_b = bigint_copy(P)
  exponent_b[1] = exponent_b[1] - 1
  -- Right-shift by 2 bits, MSB to LSB so the high bits flow into the
  -- digit below. Uses a separately-named borrow accumulator to keep the
  -- scope clean against the earlier (p+3)/8 shift in the same function.
  do
    local sqrt_borrow = 0
    for i = BIGINT_DIGITS, 1, -1 do
      local val = exponent_b[i] + sqrt_borrow * BASE
      exponent_b[i] = math.floor(val / 4)
      sqrt_borrow = val % 4
    end
  end
  local sqrt_neg_one = bigint_pow_mod(bigint_from_small(2), exponent_b)
  root = bigint_mul_mod(root, sqrt_neg_one)
  root_sq = bigint_mul_mod(root, root)
  return bigint_cmp(root_sq, x2) == 0
end

--- Run Solana's `find_program_address` against the given seed strings
--- and program id. Returns the base58 address and the bump byte that
--- produced the off-curve candidate.
function M.find_program_address(seeds, program_id)
  local program_bytes = base58.decode(program_id)
  if #program_bytes ~= 32 then
    error('program id must decode to 32 bytes')
  end
  for bump = 255, 0, -1 do
    local pieces = {}
    for i = 1, #seeds do
      pieces[#pieces + 1] = seeds[i]
    end
    pieces[#pieces + 1] = string.char(bump)
    pieces[#pieces + 1] = program_bytes
    pieces[#pieces + 1] = PROGRAM_DERIVED_ADDRESS_SEED
    local candidate = crypto.sha256(table.concat(pieces))
    if not is_on_curve(candidate) then
      return base58.encode(candidate), bump
    end
  end
  error('unable to find program address')
end

--- Derive the Associated Token Account address for the given owner / mint
--- / token program. Mirrors `ruby/lib/mpp/methods/solana/associated_token.rb`
--- and the Rust spine's `AssociatedToken::find_program_address`.
function M.derive(owner, mint, token_program)
  local owner_bytes = base58.decode(owner)
  local token_bytes = base58.decode(token_program)
  local mint_bytes = base58.decode(mint)
  if #owner_bytes ~= 32 or #token_bytes ~= 32 or #mint_bytes ~= 32 then
    error('ATA derivation requires base58 inputs that decode to 32 bytes')
  end
  local address, _bump = M.find_program_address(
    { owner_bytes, token_bytes, mint_bytes },
    'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
  )
  return address
end

M.PROGRAM_DERIVED_ADDRESS_SEED = PROGRAM_DERIVED_ADDRESS_SEED

-- Test-only handle on the bignum on-curve primitive. Lets the spec pin
-- canonical fixtures (the all-zero candidate, the encoded USDC public key)
-- without having to drive `find_program_address` through 256 hash rounds.
M._internals = {
  is_on_curve = is_on_curve,
  bigint_from_bytes = bigint_from_bytes,
}

return M
