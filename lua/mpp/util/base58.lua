--[[
Bitcoin / Solana alphabet Base58 encoder and decoder.

Mirrors `ruby/lib/mpp/methods/solana/base58.rb`. Used to encode and decode
Solana public keys, signatures, and blockhashes. Pure LuaJIT, no external
dependency. Internally accumulates a big-integer represented as a
little-endian array of bytes so the implementation works on Lua numbers
that cannot hold full 32-byte values natively.

The leading-zero rule matches Bitcoin / Solana: every leading 0x00 byte
in the input maps to a leading '1' character in the encoded output, and
every leading '1' in the encoded string maps to a leading 0x00 byte in
the decoded output.
]]

local M = {}

local ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

-- Build an index table once at module load. Cached as an upvalue so each
-- decode call avoids the per-call construction cost on LuaJIT's hot path.
local DECODE = {}
for i = 1, #ALPHABET do
  DECODE[ALPHABET:sub(i, i)] = i - 1
end

-- Add a small Lua-number multiplier to a base-256 little-endian big-integer
-- represented as a table of bytes. Operates in place.
local function bigint_add_mul(digits, multiplier, addend)
  local carry = addend
  for i = 1, #digits do
    local value = (digits[i] * multiplier) + carry
    digits[i] = value % 256
    carry = math.floor(value / 256)
  end
  while carry > 0 do
    digits[#digits + 1] = carry % 256
    carry = math.floor(carry / 256)
  end
  -- When the accumulator starts empty and the addend is zero, no digit is
  -- pushed; leave it that way so all-zero inputs encode cleanly.
end

-- Divide a base-256 little-endian big-integer by a small Lua-number divisor
-- in place. Returns the remainder.
local function bigint_divmod(digits, divisor)
  local remainder = 0
  for i = #digits, 1, -1 do
    local value = remainder * 256 + digits[i]
    digits[i] = math.floor(value / divisor)
    remainder = value % divisor
  end
  -- Strip the high-order zeroes so the caller's positive check still works.
  while #digits > 0 and digits[#digits] == 0 do
    digits[#digits] = nil
  end
  return remainder
end

--- Encode binary bytes as a Base58 string.
-- @param binary string of raw bytes
-- @return Base58-encoded string
function M.encode(binary)
  if binary == nil or binary == '' then
    return ''
  end
  -- Count leading zero bytes; each becomes a leading '1' in the output.
  local leading = 0
  while leading < #binary and binary:byte(leading + 1) == 0 do
    leading = leading + 1
  end
  -- Build a big-integer little-endian; start from the most-significant byte
  -- and multiply by 256 each iteration. The accumulator starts empty so an
  -- all-zero input stays empty after the loop (and the caller emits only
  -- the leading '1' characters from the leading-zero count).
  local digits = {}
  for i = 1, #binary do
    bigint_add_mul(digits, 256, binary:byte(i))
  end
  -- Repeatedly divide by 58, collecting remainders as alphabet characters.
  local chars = {}
  while #digits > 0 do
    local remainder = bigint_divmod(digits, 58)
    chars[#chars + 1] = ALPHABET:sub(remainder + 1, remainder + 1)
  end
  for _ = 1, leading do
    chars[#chars + 1] = '1'
  end
  -- chars holds the encoding in reverse order. Walk back-to-front so the
  -- final string starts with the most-significant Base58 digit.
  local out = {}
  for i = #chars, 1, -1 do
    out[#out + 1] = chars[i]
  end
  return table.concat(out)
end

--- Decode a Base58 string into binary bytes.
-- @param value Base58-encoded string
-- @return raw byte string
function M.decode(value)
  if value == nil or value == '' then
    return ''
  end
  -- Count leading '1' characters; each becomes a leading zero byte.
  local leading = 0
  while leading < #value and value:sub(leading + 1, leading + 1) == '1' do
    leading = leading + 1
  end
  local digits = {}
  for i = 1, #value do
    local index = DECODE[value:sub(i, i)]
    if index == nil then
      error('invalid base58 character at position ' .. tostring(i))
    end
    bigint_add_mul(digits, 58, index)
  end
  -- Emit bytes from the big-integer most-significant first; strip the
  -- accumulator's trailing zeroes inside divmod, then reverse.
  local bytes = {}
  for i = 1, #digits do
    bytes[#bytes + 1] = string.char(digits[i])
  end
  local out = {}
  for _ = 1, leading do
    out[#out + 1] = '\0'
  end
  for i = #bytes, 1, -1 do
    out[#out + 1] = bytes[i]
  end
  return table.concat(out)
end

M.ALPHABET = ALPHABET

return M
