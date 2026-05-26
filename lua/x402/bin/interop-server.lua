local socket = require("socket")
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("dkjson")
local sodium = require("luasodium")
local luazen = require("luazen")

-- Resolve the `lua/` package root relative to this bin script so the L8
-- settle helpers in `x402/exact_settle.lua` are loadable regardless of the
-- caller's working directory. The interop harness spawns this script with
-- `lua ../../lua/x402/bin/interop-server.lua` from its own cwd, so a static
-- `require('x402.exact_settle')` would otherwise fail.
do
  local script_path = arg and arg[0] or debug.getinfo(1, 'S').source:gsub('^@', '')
  local script_dir = script_path:match('(.*/)') or './'
  local lua_root = script_dir .. '../..'
  package.path = lua_root .. '/?.lua;' .. lua_root .. '/?/init.lua;' .. package.path
end

local exact_settle = require('x402.exact_settle')

-- luasec (https) is optional at require time so the static probe and
-- non-HTTPS RPC flows still load on environments without OpenSSL bindings.
-- We require peer TLS verification whenever the RPC URL is https://...,
-- unless X402_INTEROP_RPC_INSECURE=1 is explicitly set for local dev.
local ok_https, https = pcall(require, "ssl.https")
if not ok_https then
  https = nil
end

local function raw_json(value)
  return { __raw_json = value }
end

local function json_string(value)
  return '"' .. tostring(value):gsub("\\", "\\\\"):gsub('"', '\\"') .. '"'
end

local function json_object(fields)
  local parts = {}
  for _, field in ipairs(fields) do
    local key = field[1]
    local value = field[2]
    if type(value) == "boolean" then
      table.insert(parts, json_string(key) .. ":" .. tostring(value))
    elseif type(value) == "number" then
      table.insert(parts, json_string(key) .. ":" .. tostring(value))
    elseif type(value) == "table" and value.__raw_json then
      table.insert(parts, json_string(key) .. ":" .. value.__raw_json)
    elseif type(value) == "table" then
      local items = {}
      for _, item in ipairs(value) do
        table.insert(items, json_string(item))
      end
      table.insert(parts, json_string(key) .. ":[" .. table.concat(items, ",") .. "]")
    else
      table.insert(parts, json_string(key) .. ":" .. json_string(value))
    end
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function read_headers(client)
  local headers = {}
  while true do
    local line = client:receive("*l")
    if not line or line == "" then
      break
    end

    local name, value = line:match("^([^:]+):%s*(.*)$")
    if name then
      headers[name:lower()] = value
    end
  end
  return headers
end

local function header_value(headers, name)
  return headers[name:lower()]
end

local function must_json_decode(raw, label)
  local decoded, _, decode_error = json.decode(raw, 1, nil)
  if decoded == nil then
    error(label .. " JSON decode failed: " .. tostring(decode_error))
  end
  return decoded
end

local function must_json_encode(value, label)
  local encoded = json.encode(value)
  if type(encoded) ~= "string" then
    error(label .. " JSON encode failed")
  end
  return encoded
end

local base64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local base64_lookup = {}
for index = 1, #base64_alphabet do
  base64_lookup[base64_alphabet:sub(index, index)] = index - 1
end

local function base64_decode(input)
  if type(input) ~= "string" or input == "" then
    return nil, "empty payment header"
  end

  local clean = input:gsub("%s", "")
  if clean:find("[^A-Za-z0-9+/=]") then
    return nil, "invalid base64 character"
  end

  local output = {}
  local buffer = 0
  local bits = 0
  local padding_started = false

  for index = 1, #clean do
    local char = clean:sub(index, index)
    if char == "=" then
      padding_started = true
    else
      if padding_started then
        return nil, "invalid base64 padding"
      end

      local value = base64_lookup[char]
      if value == nil then
        return nil, "invalid base64 character"
      end

      buffer = (buffer << 6) | value
      bits = bits + 6
      if bits >= 8 then
        bits = bits - 8
        local byte = (buffer >> bits) & 0xff
        table.insert(output, string.char(byte))
        buffer = buffer & ((1 << bits) - 1)
      end
    end
  end

  return table.concat(output)
end

local function base64_encode(input)
  local output = {}
  local index = 1

  while index <= #input do
    local byte1 = input:byte(index) or 0
    local byte2 = input:byte(index + 1) or 0
    local byte3 = input:byte(index + 2) or 0
    local triple = (byte1 << 16) | (byte2 << 8) | byte3

    local char1 = ((triple >> 18) & 0x3f) + 1
    local char2 = ((triple >> 12) & 0x3f) + 1
    local char3 = ((triple >> 6) & 0x3f) + 1
    local char4 = (triple & 0x3f) + 1

    table.insert(output, base64_alphabet:sub(char1, char1))
    table.insert(output, base64_alphabet:sub(char2, char2))
    if index + 1 <= #input then
      table.insert(output, base64_alphabet:sub(char3, char3))
    else
      table.insert(output, "=")
    end
    if index + 2 <= #input then
      table.insert(output, base64_alphabet:sub(char4, char4))
    else
      table.insert(output, "=")
    end

    index = index + 3
  end

  return table.concat(output)
end

local function base58_decode(value)
  local decoded = luazen.b58decode(value)
  if type(decoded) ~= "string" or #decoded ~= 32 then
    error("invalid base58 public key")
  end
  return decoded
end

local function base58_encode(value)
  return luazen.b58encode(value)
end

-- Pure-Lua 256-bit modular arithmetic over the Ed25519 prime field.
--
-- This block exists only to support independent Associated Token Account PDA
-- derivation, which mirrors the canonical Rust spine in
-- `rust/crates/x402/src/protocol/schemes/exact/verify.rs::get_associated_token_address`
-- and the Solana Ed25519 `find_program_address` algorithm. luasodium does not
-- expose `crypto_core_ed25519_is_valid_point` in our pinned package surface
-- (see `rockspec` and `luasodium 2.4.x` modules), so we implement Edwards
-- point decompression directly to perform the off-curve check that
-- `find_program_address` requires when choosing a bump seed.
--
-- Limb layout: ten 26-bit base-2^26 limbs, little-endian. Multiplication of
-- two limbs is bounded by 2^52, which is safely within Lua 5.4's 63-bit
-- signed integer arithmetic. The representation tolerates non-canonical
-- limb values during arithmetic and is normalized via `bn_reduce_mod_p`.
local BN_LIMB_BITS = 26
local BN_LIMB_BASE = 1 << BN_LIMB_BITS
local BN_LIMB_MASK = BN_LIMB_BASE - 1
local BN_LIMBS = 10

local function bn_zero()
  local value = {}
  for index = 1, BN_LIMBS do
    value[index] = 0
  end
  return value
end

local function bn_clone(a)
  local copy = {}
  for index = 1, BN_LIMBS do
    copy[index] = a[index]
  end
  return copy
end

local function bn_from_uint(uint)
  local value = bn_zero()
  local index = 1
  while uint > 0 do
    value[index] = uint & BN_LIMB_MASK
    uint = uint >> BN_LIMB_BITS
    index = index + 1
  end
  return value
end

local function bn_from_bytes_le(bytes)
  -- Convert 32-byte little-endian field element into the limb representation.
  if #bytes ~= 32 then
    error("bn_from_bytes_le expects 32 bytes")
  end
  local value = bn_zero()
  local bit_position = 0
  for byte_index = 1, 32 do
    local byte = bytes:byte(byte_index)
    local limb_index = (bit_position // BN_LIMB_BITS) + 1
    local bit_offset = bit_position % BN_LIMB_BITS
    value[limb_index] = (value[limb_index] or 0) | ((byte << bit_offset) & BN_LIMB_MASK)
    local remaining = 8 - (BN_LIMB_BITS - bit_offset)
    if remaining > 0 then
      value[limb_index + 1] = (value[limb_index + 1] or 0) | (byte >> (8 - remaining))
    end
    bit_position = bit_position + 8
  end
  return value
end

-- Ed25519 prime p = 2^255 - 19. We carry an 11th limb during arithmetic and
-- fold high bits back via the identity 2^255 == 19 mod p. Two reduce passes
-- guarantee a result strictly below p for inputs up to 2^260.
local ED25519_P_BYTES = string.char(
  0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
)
local ED25519_P = bn_from_bytes_le(ED25519_P_BYTES)

local function bn_carry_normalize(limbs, limb_count)
  -- Propagate carries; limbs are not yet reduced mod p.
  local carry = 0
  for index = 1, limb_count do
    local value = (limbs[index] or 0) + carry
    limbs[index] = value & BN_LIMB_MASK
    carry = value >> BN_LIMB_BITS
  end
  return carry
end

local function bn_reduce_mod_p(limbs)
  -- Fold limbs above bit 255 back into the low limbs using 2^255 == 19 mod p.
  -- After two passes the value is guaranteed to be in [0, p).
  --
  -- Limb layout: limb[i] represents value * 2^(26*(i-1)). So limb[10] starts
  -- at bit 234 and bit `b` of limb[10] is bit (234+b) of the number. Bit 255
  -- corresponds to bit 21 of limb[10]. limb[11] starts at bit 260 and folds
  -- via 2^260 ≡ 19 * 2^5 ≡ 608 mod p (each unit of limb[11] folds as
  -- 19 * 2^5, equivalently 32 units of the "bit 255 fold").
  for _ = 1, 2 do
    bn_carry_normalize(limbs, BN_LIMBS + 1)
    local top = limbs[BN_LIMBS] or 0
    -- Bits 21..25 of limb[10] represent multiples of 2^255 .. 2^259.
    -- limbs[11] represents multiples of 2^260; one unit of limb[11] is
    -- 32 units of the 2^255 fold (since 2^260 = 32 * 2^255).
    local high = (top >> 21) + ((limbs[BN_LIMBS + 1] or 0) << 5)
    limbs[BN_LIMBS] = top & 0x001fffff
    limbs[BN_LIMBS + 1] = 0
    if high ~= 0 then
      local carry = high * 19
      local index = 1
      while carry ~= 0 do
        carry = (limbs[index] or 0) + carry
        limbs[index] = carry & BN_LIMB_MASK
        carry = carry >> BN_LIMB_BITS
        index = index + 1
      end
    end
  end

  -- Conditional subtract of p if still >= p.
  local greater_or_equal = true
  for index = BN_LIMBS, 1, -1 do
    local left = limbs[index] or 0
    local right = ED25519_P[index]
    if left > right then
      break
    elseif left < right then
      greater_or_equal = false
      break
    end
  end
  if greater_or_equal then
    local borrow = 0
    for index = 1, BN_LIMBS do
      local diff = (limbs[index] or 0) - ED25519_P[index] - borrow
      if diff < 0 then
        diff = diff + BN_LIMB_BASE
        borrow = 1
      else
        borrow = 0
      end
      limbs[index] = diff
    end
  end
  return limbs
end

local function bn_add_mod_p(a, b)
  local result = {}
  local carry = 0
  for index = 1, BN_LIMBS do
    local sum = a[index] + b[index] + carry
    result[index] = sum & BN_LIMB_MASK
    carry = sum >> BN_LIMB_BITS
  end
  result[BN_LIMBS + 1] = carry
  return bn_reduce_mod_p(result)
end

local function bn_sub_mod_p(a, b)
  -- Compute a + (p - b) mod p to avoid signed-limb juggling.
  local complement = {}
  local borrow = 0
  for index = 1, BN_LIMBS do
    local diff = ED25519_P[index] - b[index] - borrow
    if diff < 0 then
      diff = diff + BN_LIMB_BASE
      borrow = 1
    else
      borrow = 0
    end
    complement[index] = diff
  end
  return bn_add_mod_p(a, complement)
end

local function bn_mul_mod_p(a, b)
  -- Schoolbook multiplication into a 2*BN_LIMBS buffer, then fold.
  local product = {}
  for index = 1, BN_LIMBS * 2 do
    product[index] = 0
  end
  for i = 1, BN_LIMBS do
    local ai = a[i]
    if ai ~= 0 then
      local carry = 0
      for j = 1, BN_LIMBS do
        local sum = product[i + j - 1] + ai * b[j] + carry
        product[i + j - 1] = sum & BN_LIMB_MASK
        carry = sum >> BN_LIMB_BITS
      end
      product[i + BN_LIMBS] = product[i + BN_LIMBS] + carry
    end
  end
  -- Fold limbs [BN_LIMBS+1 .. 2*BN_LIMBS] back into the low half. Each high
  -- limb at position BN_LIMBS+k represents 2^(26*(BN_LIMBS+k-1)) = 2^(260 + 26*(k-1)).
  -- Since 2^260 ≡ 608 mod p (= 19 * 2^5; 2^255 ≡ 19), folding adds
  -- high_limb * 608 at low position k.
  local FOLD_FACTOR = 608
  local low = {}
  for index = 1, BN_LIMBS do
    low[index] = product[index] or 0
  end
  low[BN_LIMBS + 1] = 0
  for index = 1, BN_LIMBS do
    local high_limb = product[BN_LIMBS + index] or 0
    if high_limb ~= 0 then
      local carry = high_limb * FOLD_FACTOR
      local target = index
      while carry ~= 0 do
        carry = (low[target] or 0) + carry
        low[target] = carry & BN_LIMB_MASK
        carry = carry >> BN_LIMB_BITS
        target = target + 1
      end
    end
  end
  return bn_reduce_mod_p(low)
end

local function bn_pow_mod_p(base, exponent_bytes)
  -- exponent_bytes is little-endian byte string up to 32 bytes representing
  -- an exponent strictly less than p. Implements square-and-multiply.
  local result = bn_from_uint(1)
  local accumulator = bn_clone(base)
  for byte_index = 1, #exponent_bytes do
    local byte = exponent_bytes:byte(byte_index)
    for bit = 0, 7 do
      if (byte & (1 << bit)) ~= 0 then
        result = bn_mul_mod_p(result, accumulator)
      end
      accumulator = bn_mul_mod_p(accumulator, accumulator)
    end
  end
  return result
end

local function bn_is_zero(a)
  for index = 1, BN_LIMBS do
    if (a[index] or 0) ~= 0 then
      return false
    end
  end
  return true
end

local function bn_equals(a, b)
  for index = 1, BN_LIMBS do
    if (a[index] or 0) ~= (b[index] or 0) then
      return false
    end
  end
  return true
end

local function bn_low_bit(a)
  return (a[1] or 0) & 1
end

-- Fermat inverse: a^(p-2) mod p. p-2 little-endian.
local ED25519_P_MINUS_TWO_BYTES = string.char(
  0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
)
-- (p+3)/8 little-endian, used for tonelli-style sqrt because p ≡ 5 mod 8.
local ED25519_SQRT_EXPONENT_BYTES = string.char(
  0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f
)
-- (p-1)/4 little-endian, used to compute I = 2^((p-1)/4) for the sqrt fix-up.
local ED25519_I_EXPONENT_BYTES = string.char(
  0xfb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f
)

local function bn_inv_mod_p(a)
  return bn_pow_mod_p(a, ED25519_P_MINUS_TWO_BYTES)
end

local function bn_mod_sqrt(a)
  -- For p ≡ 5 mod 8, candidate = a^((p+3)/8). Either candidate^2 == a, or
  -- candidate * I works (where I^2 == -1). Otherwise no square root exists.
  local candidate = bn_pow_mod_p(a, ED25519_SQRT_EXPONENT_BYTES)
  local candidate_squared = bn_mul_mod_p(candidate, candidate)
  if bn_equals(candidate_squared, a) then
    return candidate
  end
  local i_value = bn_pow_mod_p(bn_from_uint(2), ED25519_I_EXPONENT_BYTES)
  local fixed = bn_mul_mod_p(candidate, i_value)
  local fixed_squared = bn_mul_mod_p(fixed, fixed)
  if bn_equals(fixed_squared, a) then
    return fixed
  end
  return nil
end

-- Ed25519 curve parameter d = -121665/121666 mod p.
local function compute_ed25519_d()
  local numerator = bn_sub_mod_p(bn_from_uint(0), bn_from_uint(121665))
  local denominator_inverse = bn_inv_mod_p(bn_from_uint(121666))
  return bn_mul_mod_p(numerator, denominator_inverse)
end
local ED25519_D = compute_ed25519_d()
local BN_ONE = bn_from_uint(1)

local function ed25519_on_curve(point_bytes)
  -- Edwards point decompression mirroring Solana's `is_on_curve` check.
  -- The sign bit lives in bit 7 of the final byte; the remaining 255 bits
  -- encode the y coordinate. The point is on-curve iff x^2 (recovered via
  -- the curve equation) admits a square root in F_p and parity matches.
  if type(point_bytes) ~= "string" or #point_bytes ~= 32 then
    return false
  end
  local sign_bit = (point_bytes:byte(32) >> 7) & 1
  local masked = point_bytes:sub(1, 31) .. string.char(point_bytes:byte(32) & 0x7f)
  local y = bn_from_bytes_le(masked)
  local y_squared = bn_mul_mod_p(y, y)
  local numerator = bn_sub_mod_p(y_squared, BN_ONE)
  local denominator = bn_add_mod_p(bn_mul_mod_p(ED25519_D, y_squared), BN_ONE)
  if bn_is_zero(denominator) then
    return false
  end
  local x_squared = bn_mul_mod_p(numerator, bn_inv_mod_p(denominator))
  local x = bn_mod_sqrt(x_squared)
  if x == nil then
    return false
  end
  if bn_is_zero(x) and sign_bit ~= 0 then
    return false
  end
  if bn_low_bit(x) ~= sign_bit then
    -- Either choice of x is acceptable for the on-curve check.
    x = bn_sub_mod_p(bn_from_uint(0), x)
  end
  local x_squared_check = bn_mul_mod_p(x, x)
  return bn_equals(x_squared_check, x_squared)
end

-- Mirrors Solana's `Pubkey::find_program_address` (and the Rust spine helper
-- `get_associated_token_address` in `rust/crates/x402/src/protocol/schemes/exact/verify.rs`
-- at the line that calls `Pubkey::find_program_address(seeds, &ata_program)`).
-- Iterates bump from 255 downward, hashing
-- `concat(seeds) || bump || program_id || "ProgramDerivedAddress"`, and
-- returns the first SHA-256 digest that is off the Ed25519 curve.
local PDA_MARKER = "ProgramDerivedAddress"
local function find_program_address(seeds, program_id_bytes)
  local seed_concat = table.concat(seeds)
  for bump = 255, 0, -1 do
    local candidate = sodium.crypto_hash_sha256(
      seed_concat .. string.char(bump) .. program_id_bytes .. PDA_MARKER
    )
    if not ed25519_on_curve(candidate) then
      return candidate, bump
    end
  end
  error("unable to derive program address")
end

-- Independently re-derives the expected destination Associated Token Account
-- for `(payTo, tokenProgram, mint)`. Equivalent to the Rust spine helper
-- `get_associated_token_address` in `rust/crates/x402/src/protocol/schemes/exact/verify.rs`
-- which uses seeds `[owner.as_ref(), token_program.as_ref(), mint.as_ref()]`
-- with the SPL Associated Token Account program id.
local function derive_associated_token_address(pay_to_bytes, token_program_bytes, mint_bytes, ata_program_bytes)
  local seeds = { pay_to_bytes, token_program_bytes, mint_bytes }
  local address = find_program_address(seeds, ata_program_bytes)
  return address
end

local function read_short_vec(bytes, offset)
  local value = 0
  local shift = 0
  local index = offset
  while true do
    if index > #bytes then
      error("short vec extends beyond input")
    end
    local byte = bytes:byte(index)
    value = value | ((byte & 0x7f) << shift)
    index = index + 1
    if (byte & 0x80) == 0 then
      return value, index
    end
    shift = shift + 7
    if shift > 28 then
      error("short vec is too long")
    end
  end
end

local function uint64_le(bytes)
  if #bytes ~= 8 then
    error("expected 8 byte little-endian integer")
  end
  local value = 0
  for index = 8, 1, -1 do
    value = (value << 8) | bytes:byte(index)
  end
  return value
end

local function account_key_for_index(account_keys, index)
  local value = account_keys[index + 1]
  if not value then
    error("invalid_exact_svm_payload_no_transfer_instruction")
  end
  return value
end

local function parse_versioned_transaction(transaction)
  local signature_count, signature_offset = read_short_vec(transaction, 1)
  local message_offset = signature_offset + (signature_count * 64)
  if message_offset > #transaction then
    error("transaction has no message bytes")
  end

  local message = transaction:sub(message_offset)
  if message:byte(1) ~= 0x80 then
    error("expected versioned transaction message")
  end
  if #message < 4 then
    error("transaction message header extends beyond input")
  end

  local required_signatures = message:byte(2)
  local account_count, offset = read_short_vec(message, 5)
  local account_keys = {}
  for index = 1, account_count do
    if offset + 31 > #message then
      error("message account key extends beyond input")
    end
    account_keys[index] = message:sub(offset, offset + 31)
    offset = offset + 32
  end
  if offset + 31 > #message then
    error("message recent blockhash extends beyond input")
  end
  offset = offset + 32

  local instruction_count
  instruction_count, offset = read_short_vec(message, offset)
  local instructions = {}
  for index = 1, instruction_count do
    if offset > #message then
      error("instruction program index extends beyond input")
    end
    local program_index = message:byte(offset)
    offset = offset + 1
    local account_index_count
    account_index_count, offset = read_short_vec(message, offset)
    if offset + account_index_count - 1 > #message then
      error("instruction account indexes extend beyond input")
    end
    local accounts = {}
    for account_index = 1, account_index_count do
      accounts[account_index] = message:byte(offset + account_index - 1)
    end
    offset = offset + account_index_count
    local data_length
    data_length, offset = read_short_vec(message, offset)
    if offset + data_length - 1 > #message then
      error("instruction data extends beyond input")
    end
    local data = message:sub(offset, offset + data_length - 1)
    offset = offset + data_length
    instructions[index] = { program_index = program_index, accounts = accounts, data = data }
  end

  return {
    signature_count = signature_count,
    signature_offset = signature_offset,
    message_offset = message_offset,
    message = message,
    required_signatures = required_signatures,
    account_keys = account_keys,
    instructions = instructions,
  }
end

local default_resource_path = "/protected"
-- Harness-canonical override: cross-server scenarios drive route + header
-- name via X402_INTEROP_RESOURCE_PATH and X402_INTEROP_SETTLEMENT_HEADER.
-- Resolved at startup so a single process serves a single route. Mirrors
-- the TS fixture wiring at harness/src/fixtures/typescript/exact-shared.ts
-- L62-64.
local function env_or(name, fallback)
  local value = os.getenv(name)
  if value == nil or value == "" then
    return fallback
  end
  return value
end
local resource_path = env_or("X402_INTEROP_RESOURCE_PATH", default_resource_path)
local settlement_header_name = env_or("X402_INTEROP_SETTLEMENT_HEADER", "x-fixture-settlement")
local default_network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
local default_mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
local default_amount = "1000"
local default_pay_to = "11111111111111111111111111111111"
-- `default_fee_payer` is intentionally left as the System Program placeholder
-- here: the real fee-payer is derived from the loaded facilitator keypair at
-- HTTP-server startup (see `load_facilitator_keypair` below) and overwrites
-- this local before any challenge is constructed. The placeholder never
-- reaches the wire because startup aborts with a typed error if the keypair
-- env var is missing.
local default_fee_payer = "11111111111111111111111111111111"
local loaded_facilitator_keypair = nil
local default_token_program = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
local token_2022_program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
local compute_budget_program = "ComputeBudget111111111111111111111111111111"
local memo_program = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
local lighthouse_program = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
local associated_token_program = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
local system_program = "11111111111111111111111111111111"
local max_compute_unit_price = 5000000
local max_memo_bytes = 256
-- L8 replay store. Keyed by `x402-svm-exact:consumed:<base58_signature>`,
-- populated AFTER `getSignatureStatuses` confirms the broadcast — never
-- pre-claimed. In-process memory is sufficient for the interop server
-- (single-process fixture). Production deployments should swap this for
-- the shared-dict store in `mpp/server/store_shared_dict.lua` to survive
-- worker process churn.
local replay_store = exact_settle.new_memory_store()
-- Confirmation polling budget. Bounded by the count of attempts so the
-- loop always terminates within roughly the blockhash validity window
-- (~150 slots × ~400ms ≈ 60s). Tunable via env for interop probes.
local confirmation_attempts = tonumber(os.getenv("X402_INTEROP_CONFIRMATION_ATTEMPTS")) or 30
local confirmation_delay_seconds = tonumber(os.getenv("X402_INTEROP_CONFIRMATION_DELAY_SECONDS")) or 1
local capability_payload = {
  { "implementation", "lua" },
  { "role", "server" },
  { "capabilities", { "exact" } }
}

local function read_env(name, fallback)
  local value = os.getenv(name)
  if value == nil or value == "" then
    return fallback
  end
  return value
end

local function normalize_amount(price)
  local raw = tostring(price)
  local value = raw:match("^%s*(.-)%s*$")
  value = value:gsub("^%$", "")
  value = value:match("^(%S+)") or value

  -- Fail-fast on malformed prices to keep parity with the Rust x402 spine,
  -- which rejects unparseable amounts rather than advertising/verifying a
  -- silent fallback that does not match the requested configuration.
  local whole, fraction = value:match("^(%d+)%.?(%d*)$")
  if not whole then
    error("invalid X402_INTEROP_PRICE: " .. raw)
  end
  if #fraction > 6 then
    error("invalid X402_INTEROP_PRICE (more than 6 decimals): " .. raw)
  end

  fraction = fraction .. string.rep("0", 6 - #fraction)
  return tostring((tonumber(whole) * 1000000) + tonumber(fraction))
end

local function trim(value)
  return tostring(value):match("^%s*(.-)%s*$")
end

-- Token-2022 stablecoin mints. Mirrors
-- `rust/crates/x402/src/protocol/schemes/exact/types.rs::stablecoin_uses_token_2022`
-- which returns true for USDG, PYUSD, and CASH (across mainnet and devnet).
-- Drifting from this set causes the Lua server to advertise/verify the
-- legacy SPL Token program for Token-2022 mints, which the Rust verifier
-- rejects.
local token_2022_mints = {
  ["2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"] = true, -- USDG mainnet
  ["4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"] = true, -- USDG devnet
  ["2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"] = true, -- PYUSD mainnet
  ["CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"] = true, -- PYUSD devnet
  ["CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"] = true, -- CASH mainnet
}

local function token_program_for_mint(mint)
  if token_2022_mints[mint] then
    return token_2022_program
  end
  return default_token_program
end

local function exact_offered_mints()
  local mints = { read_env("X402_INTEROP_MINT", default_mint) }
  local extra_mints = read_env("X402_INTEROP_EXTRA_OFFERED_MINTS", "")
  for raw_mint in extra_mints:gmatch("([^,]+)") do
    local mint = trim(raw_mint)
    if mint ~= "" then
      table.insert(mints, mint)
    end
  end
  return mints
end

local function required_env(name)
  local value = os.getenv(name)
  if value == nil or value == "" then
    error(name .. " is required")
  end
  return value
end

local function exact_requirement_table(asset)
  local mint = asset or read_env("X402_INTEROP_MINT", default_mint)
  return {
    scheme = "exact",
    network = read_env("X402_INTEROP_NETWORK", default_network),
    asset = mint,
    amount = normalize_amount(read_env("X402_INTEROP_PRICE", "$0.001")),
    payTo = read_env("X402_INTEROP_PAY_TO", default_pay_to),
    maxTimeoutSeconds = 60,
    extra = {
      decimals = 6,
      feePayer = read_env("X402_INTEROP_FEE_PAYER", default_fee_payer),
      tokenProgram = token_program_for_mint(mint),
    }
  }
end

local function exact_requirement_json(asset)
  local mint = asset or read_env("X402_INTEROP_MINT", default_mint)
  local extra = json_object({
    { "decimals", 6 },
    { "feePayer", read_env("X402_INTEROP_FEE_PAYER", default_fee_payer) },
    { "tokenProgram", token_program_for_mint(mint) }
  })

  return json_object({
    { "scheme", "exact" },
    { "network", read_env("X402_INTEROP_NETWORK", default_network) },
    { "asset", mint },
    { "amount", normalize_amount(read_env("X402_INTEROP_PRICE", "$0.001")) },
    { "payTo", read_env("X402_INTEROP_PAY_TO", default_pay_to) },
    { "maxTimeoutSeconds", 60 },
    { "extra", raw_json(extra) }
  })
end

local function exact_accepts_json()
  local offers = {}
  for _, mint in ipairs(exact_offered_mints()) do
    table.insert(offers, exact_requirement_json(mint))
  end
  return "[" .. table.concat(offers, ",") .. "]"
end

local function exact_challenge_json()
  return json_object({
    { "x402Version", 2 },
    { "accepts", raw_json(exact_accepts_json()) },
    -- Canonical x402 v2 PaymentRequiredEnvelope.resource is `ResourceInfo {
    -- url, description?, mimeType? }` (see rust/crates/x402
    -- protocol/schemes/exact/types.rs::ResourceInfo). Rust clients parse the
    -- PAYMENT-REQUIRED header with serde and the whole envelope is dropped
    -- if `url` is missing, so an alternate shape like `{ type, uri }` breaks
    -- Rust client to Lua server interop.
    { "resource", raw_json(json_object({ { "url", resource_path } })) }
  })
end

local function exact_payment_required_header()
  return base64_encode(exact_challenge_json())
end

local function accepted_requirement_matches(accepted)
  if type(accepted) ~= "table" or type(accepted.extra) ~= "table" then
    return false
  end
  for _, mint in ipairs(exact_offered_mints()) do
    local expected = exact_requirement_table(mint)
    if accepted.scheme == expected.scheme and
      accepted.network == expected.network and
      accepted.asset == expected.asset and
      tostring(accepted.amount) == expected.amount and
      accepted.payTo == expected.payTo and
      tostring(accepted.extra.decimals) == tostring(expected.extra.decimals) and
      accepted.extra.feePayer == expected.extra.feePayer and
      accepted.extra.tokenProgram == expected.extra.tokenProgram then
      return true
    end
  end
  return false
end

local function decode_payment_signature(payment_header)
  local decoded, decode_error = base64_decode(payment_header)
  if not decoded then
    error("malformed PAYMENT-SIGNATURE: " .. decode_error)
  end
  return must_json_decode(decoded, "PAYMENT-SIGNATURE")
end

local function keypair_from_json_secret(raw)
  local values = must_json_decode(raw, "Solana secret key")
  if type(values) ~= "table" or #values ~= 64 then
    error("expected a 64-byte Solana secret key JSON array")
  end
  local seed = {}
  for index = 1, 32 do
    seed[index] = string.char(values[index])
  end
  local public_key, secret_key = sodium.crypto_sign_seed_keypair(table.concat(seed))
  if type(public_key) ~= "string" or #public_key ~= 32 or type(secret_key) ~= "string" or #secret_key ~= 64 then
    error("failed to derive Ed25519 keypair")
  end
  return { public_key = public_key, secret_key = secret_key }
end

local function instruction_program(instruction, account_keys)
  return account_key_for_index(account_keys, instruction.program_index)
end

local function verify_compute_limit_instruction(instruction, account_keys)
  if instruction_program(instruction, account_keys) ~= base58_decode(compute_budget_program) or
      #instruction.data ~= 5 or instruction.data:byte(1) ~= 2 then
    error("invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction")
  end
end

local function verify_compute_price_instruction(instruction, account_keys)
  if instruction_program(instruction, account_keys) ~= base58_decode(compute_budget_program) or
      #instruction.data ~= 9 or instruction.data:byte(1) ~= 3 then
    error("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction")
  end
  if uint64_le(instruction.data:sub(2, 9)) > max_compute_unit_price then
    error("invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high")
  end
end

local function parse_transfer_checked_instruction(instruction, account_keys)
  local program = instruction_program(instruction, account_keys)
  local allowed_token_program = base58_decode(default_token_program)
  local allowed_token_2022_program = base58_decode(token_2022_program)
  if program ~= allowed_token_program and program ~= allowed_token_2022_program then
    error("invalid_exact_svm_payload_transaction_transfer_program")
  end
  if #instruction.accounts < 4 or #instruction.data ~= 10 or instruction.data:byte(1) ~= 12 then
    error("invalid_exact_svm_payload_transaction_transfer_checked")
  end
  return {
    source = account_key_for_index(account_keys, instruction.accounts[1]),
    mint = account_key_for_index(account_keys, instruction.accounts[2]),
    destination = account_key_for_index(account_keys, instruction.accounts[3]),
    authority = account_key_for_index(account_keys, instruction.accounts[4]),
    amount = uint64_le(instruction.data:sub(2, 9)),
    decimals = instruction.data:byte(10),
    token_program = program,
  }
end

local function valid_destination_ata_create_instruction(instruction, account_keys, requirement, transfer)
  if #instruction.data > 1 then
    return false
  end
  if #instruction.data == 1 and instruction.data:byte(1) ~= 0 and instruction.data:byte(1) ~= 1 then
    return false
  end
  if #instruction.accounts < 6 then
    return false
  end
  return account_key_for_index(account_keys, instruction.accounts[2]) == transfer.destination and
    account_key_for_index(account_keys, instruction.accounts[3]) == base58_decode(requirement.payTo) and
    account_key_for_index(account_keys, instruction.accounts[4]) == transfer.mint and
    account_key_for_index(account_keys, instruction.accounts[5]) == base58_decode(system_program) and
    account_key_for_index(account_keys, instruction.accounts[6]) == transfer.token_program
end

local function verify_optional_instructions(instructions, account_keys, requirement, transfer)
  local memo_count = 0
  for index = 4, #instructions do
    local instruction = instructions[index]
    local program = instruction_program(instruction, account_keys)
    if program == base58_decode(memo_program) then
      memo_count = memo_count + 1
      if #instruction.data > max_memo_bytes then
        error("extra.memo exceeds maximum 256 bytes")
      end
      if requirement.extra.memo and instruction.data ~= requirement.extra.memo then
        error("invalid_exact_svm_payload_transaction_memo")
      end
    elseif program == base58_decode(lighthouse_program) then
      -- Intentional spine parity: the Rust spine
      -- (`rust/crates/x402/src/protocol/schemes/exact/verify.rs:266`) and the TypeScript
      -- spine (`typescript/packages/x402/src/facilitator/exact/scheme.ts:300`)
      -- both pass Lighthouse through unconditionally — no discriminator
      -- allowlist, no account-count cap. Adding one here would reject
      -- real Phantom/Solflare mainnet payments and break interop. See
      -- `notes/lighthouse-allowlist-tracking.md` for the parity ledger.
    elseif program == base58_decode(associated_token_program) and valid_destination_ata_create_instruction(instruction, account_keys, requirement, transfer) then
      -- Destination ATA creation may be included before settlement.
    else
      local reasons = {
        "invalid_exact_svm_payload_unknown_fourth_instruction",
        "invalid_exact_svm_payload_unknown_fifth_instruction",
        "invalid_exact_svm_payload_unknown_sixth_instruction",
      }
      error(reasons[index - 3] or "invalid_exact_svm_payload_unknown_optional_instruction")
    end
  end
  if requirement.extra.memo and memo_count ~= 1 then
    error("invalid_exact_svm_payload_transaction_memo")
  end
end

-- Mirror the canonical Rust spine sweep in
-- `rust/crates/x402/src/protocol/schemes/exact/verify.rs::verify_managed_signers_not_instruction_accounts`
-- (introduced in commit 498a6ed, "fix(exact): reject fee payer instruction accounts").
-- Every instruction account position across every instruction MUST NOT name
-- the server's fee-payer. The only legitimate exception is the ATA-create
-- instruction's funding payer at accounts[1] (1-based), where the fee-payer
-- is expected to front the rent for the destination token account. The
-- structural shape of that exception is enforced by
-- `valid_destination_ata_create_instruction`.
local function verify_fee_payer_not_instruction_account(instructions, account_keys, requirement, transfer)
  local fee_payer = base58_decode(requirement.extra.feePayer)
  local ata_program_bytes = base58_decode(associated_token_program)
  for _, instruction in ipairs(instructions) do
    local is_ata_create =
      instruction_program(instruction, account_keys) == ata_program_bytes
      and valid_destination_ata_create_instruction(instruction, account_keys, requirement, transfer)
    for position, account_index in ipairs(instruction.accounts) do
      if account_key_for_index(account_keys, account_index) == fee_payer then
        if not (is_ata_create and position == 1) then
          error("invalid_exact_svm_payload_transaction_fee_payer_in_instruction_accounts")
        end
      end
    end
  end
end

local function verify_exact_transaction(parsed, requirement)
  local instructions = parsed.instructions
  if #instructions < 3 or #instructions > 6 then
    error("invalid_exact_svm_payload_transaction_instructions_length")
  end
  verify_compute_limit_instruction(instructions[1], parsed.account_keys)
  verify_compute_price_instruction(instructions[2], parsed.account_keys)
  local transfer = parse_transfer_checked_instruction(instructions[3], parsed.account_keys)
  verify_optional_instructions(instructions, parsed.account_keys, requirement, transfer)

  local fee_payer = base58_decode(requirement.extra.feePayer)
  if transfer.authority == fee_payer or transfer.source == fee_payer then
    error("invalid_exact_svm_payload_transaction_fee_payer_transferring_funds")
  end
  verify_fee_payer_not_instruction_account(instructions, parsed.account_keys, requirement, transfer)
  if transfer.mint ~= base58_decode(requirement.asset) then
    error("invalid_exact_svm_payload_transaction_mint")
  end
  if requirement.extra.tokenProgram ~= nil
      and transfer.token_program ~= base58_decode(requirement.extra.tokenProgram) then
    error("invalid_exact_svm_payload_transaction_token_program")
  end
  if transfer.amount ~= tonumber(requirement.amount) then
    error("invalid_exact_svm_payload_transaction_amount")
  end
  if transfer.decimals ~= tonumber(requirement.extra.decimals) then
    error("invalid_exact_svm_payload_transaction_decimals")
  end
  -- Independently re-derive the expected destination ATA from
  -- (payTo, tokenProgram, mint) and compare against the transaction's
  -- transferChecked destination. Without this, a malicious client could
  -- name any writable ATA they control and receive funds despite the
  -- payTo field matching. Mirrors the Rust spine check at
  -- `verify_transfer_instruction` → `get_associated_token_address`.
  local expected_destination = derive_associated_token_address(
    base58_decode(requirement.payTo),
    transfer.token_program,
    transfer.mint,
    base58_decode(associated_token_program)
  )
  if transfer.destination ~= expected_destination then
    error("invalid_exact_svm_payload_destination_ata_mismatch")
  end
  return transfer
end

local function required_signer_index(parsed, public_key)
  for index = 1, parsed.required_signatures do
    if parsed.account_keys[index] == public_key then
      return index - 1
    end
  end
  error("fee payer not found in required signer accounts")
end

local function sign_transaction_with_fee_payer(transaction, parsed, keypair)
  local signer_index = required_signer_index(parsed, keypair.public_key)
  if signer_index >= parsed.signature_count then
    error("fee payer is not present in transaction signatures")
  end
  local signature = sodium.crypto_sign_detached(parsed.message, keypair.secret_key)
  local start = parsed.signature_offset + (signer_index * 64)
  return transaction:sub(1, start - 1) .. signature .. transaction:sub(start + 64)
end

local function verify_transaction_signatures(transaction, parsed)
  for index = 1, parsed.required_signatures do
    local signature_start = parsed.signature_offset + ((index - 1) * 64)
    local signature = transaction:sub(signature_start, signature_start + 63)
    if not sodium.crypto_sign_verify_detached(signature, parsed.message, parsed.account_keys[index]) then
      error("invalid transaction signature")
    end
  end
end

local function post_json_rpc(method, params)
  local body = must_json_encode({ jsonrpc = "2.0", id = 1, method = method, params = params }, method)
  local chunks = {}
  local url = required_env("X402_INTEROP_RPC_URL")
  local is_https = url:sub(1, 8) == "https://"
  local request = {
    url = url,
    method = "POST",
    headers = {
      ["content-type"] = "application/json",
      ["content-length"] = tostring(#body),
    },
    source = ltn12.source.string(body),
    sink = ltn12.sink.table(chunks),
  }
  local transport
  if is_https then
    if not https then
      error(method .. ": HTTPS RPC URL requires luasec (ssl.https)")
    end
    local insecure = os.getenv("X402_INTEROP_RPC_INSECURE") == "1"
    request.verify = insecure and "none" or "peer"
    request.protocol = "tlsv1_2"
    request.options = { "all", "no_sslv2", "no_sslv3", "no_tlsv1", "no_tlsv1_1" }
    transport = https
  else
    transport = http
  end
  local ok, status = transport.request(request)
  if not ok or status < 200 or status >= 300 then
    error(method .. " HTTP " .. tostring(status))
  end
  local payload = must_json_decode(table.concat(chunks), method)
  if payload.error ~= nil then
    error(method .. " RPC error: " .. must_json_encode(payload.error, method .. " error"))
  end
  return payload.result
end

local function get_account_data(public_key)
  local result = post_json_rpc("getAccountInfo", {
    base58_encode(public_key),
    { encoding = "base64" },
  })
  if result == nil or result.value == nil then
    return nil
  end
  local data = result.value.data
  if type(data) ~= "table" or type(data[1]) ~= "string" then
    return nil
  end
  local decoded, decode_error = base64_decode(data[1])
  if not decoded then
    error("account data decode failed: " .. decode_error)
  end
  return decoded
end

local function verify_token_account(public_key, expected_mint, expected_owner)
  local data = get_account_data(public_key)
  if data == nil then
    return false
  end
  if #data < 64 then
    error("token account data too short")
  end
  if data:sub(1, 32) ~= expected_mint then
    error("token account mint mismatch")
  end
  if expected_owner and data:sub(33, 64) ~= expected_owner then
    error("token account owner mismatch")
  end
  return true
end

local function has_destination_create_instruction(parsed, requirement, transfer)
  for index = 4, #parsed.instructions do
    local instruction = parsed.instructions[index]
    if instruction_program(instruction, parsed.account_keys) == base58_decode(associated_token_program) and
        valid_destination_ata_create_instruction(instruction, parsed.account_keys, requirement, transfer) then
      return true
    end
  end
  return false
end

local function verify_token_accounts_exist(parsed, requirement, transfer)
  local expected_mint = base58_decode(requirement.asset)
  if not verify_token_account(transfer.source, expected_mint, nil) then
    error("source token account does not exist")
  end
  if has_destination_create_instruction(parsed, requirement, transfer) then
    return
  end
  if not verify_token_account(transfer.destination, expected_mint, base58_decode(requirement.payTo)) then
    error("destination token account does not exist")
  end
end

-- Solana surfaces a duplicate-broadcast as a `sendTransaction` RPC error
-- whose message contains "already been processed" (or "transaction already
-- processed") BEFORE the L8 replay store reservation fires. Canonically
-- this is the same outcome as a replay-store hit, so we map the RPC error
-- to a structured `signature_consumed` table-error that `payment_error_response`
-- preserves. The classifier lives in `x402/exact_settle.lua` so it's unit-
-- testable; here we just consume it.
local function send_transaction(transaction)
  local ok, result = pcall(post_json_rpc, "sendTransaction", {
    base64_encode(transaction),
    {
      encoding = "base64",
      skipPreflight = false,
      preflightCommitment = "processed",
      maxRetries = 3,
    },
  })
  if not ok then
    if exact_settle.is_duplicate_broadcast_error(result) then
      error({
        code = "signature_consumed",
        message = "Transaction signature already consumed: " .. tostring(result),
      })
    end
    error(result)
  end
  if type(result) ~= "string" or result == "" then
    error("sendTransaction returned empty signature")
  end
  return result
end

local function settle_exact_payment(payment_header)
  local payment = decode_payment_signature(payment_header)
  if payment.x402Version ~= 2 then
    error("unsupported x402Version")
  end
  if not accepted_requirement_matches(payment.accepted) then
    error("accepted payment requirement does not match server challenge")
  end
  if type(payment.payload) ~= "table" or type(payment.payload.transaction) ~= "string" or payment.payload.transaction == "" then
    error("payment payload is missing transaction")
  end

  local transaction, transaction_decode_error = base64_decode(payment.payload.transaction)
  if not transaction then
    error("payment transaction decode failed: " .. transaction_decode_error)
  end
  local parsed = parse_versioned_transaction(transaction)
  local transfer = verify_exact_transaction(parsed, payment.accepted)
  verify_token_accounts_exist(parsed, payment.accepted, transfer)

  -- Reuse the keypair loaded and validated at startup so the public key
  -- funding the transaction is identical to the one the server advertised
  -- in `extra.feePayer`. Re-loading here would let challenge-time and
  -- settle-time keys drift apart.
  local keypair = loaded_facilitator_keypair
    or keypair_from_json_secret(required_env("X402_INTEROP_FACILITATOR_SECRET_KEY"))
  local signed_transaction = sign_transaction_with_fee_payer(transaction, parsed, keypair)
  local signed_parsed = parse_versioned_transaction(signed_transaction)
  verify_transaction_signatures(signed_transaction, signed_parsed)

  -- L8 ordering: broadcast → await `getSignatureStatuses` → put_if_absent.
  -- The replay store is touched ONLY after the network confirms the
  -- signature, so a preflight/processed return cannot mark a transaction
  -- consumed prematurely. A duplicate signature raises a canonical
  -- `signature_consumed` table-error which `payment_error_response` maps
  -- back to the wire-level error code — never a 200. See the
  -- `x402-sdk-implementation` skill's `pr-readiness.md` L8 section and
  -- the MPP `server/charge.rs` reference.
  return exact_settle.broadcast_confirm_consume({
    broadcast = function() return send_transaction(signed_transaction) end,
    rpc_call = post_json_rpc,
    replay_store = replay_store,
    confirmation_attempts = confirmation_attempts,
    confirmation_delay_seconds = confirmation_delay_seconds,
    sleep = socket.sleep,
  })
end

local function payment_required_response()
  return 402, "Payment Required", "PAYMENT-REQUIRED: " .. exact_payment_required_header() .. "\r\n", json_object({ { "error", "payment_required" } })
end

-- Map raised errors to canonical x402 error codes. Table-shaped errors
-- (e.g. `{ code = 'signature_consumed', message = ... }`) preserve their
-- canonical code so a duplicate L8 settlement is reported as
-- `signature_consumed`, not flattened to `payment_invalid` — which would
-- mask the replay-store rejection from interop clients.
local function payment_error_response(err)
  local code = "payment_invalid"
  local message
  if type(err) == "table" then
    if type(err.code) == "string" and err.code ~= "" then
      code = err.code
    end
    message = err.message or err[1] or "payment error"
  else
    message = err
  end
  return 402, "Payment Required", "PAYMENT-REQUIRED: " .. exact_payment_required_header() .. "\r\n", json_object({ { "error", code }, { "message", tostring(message) } })
end

local function response_for(path, headers)
  if path == "/health" then
    return 200, "OK", "", json_object({ { "ok", true } })
  elseif path == "/capabilities" then
    return 200, "OK", "", json_object(capability_payload)
  elseif path == "/exact" then
    return 402, "Payment Required", "PAYMENT-REQUIRED: " .. exact_payment_required_header() .. "\r\n", json_object({ { "error", "payment_required" } })
  elseif path == resource_path then
    local payment_signature = header_value(headers, "PAYMENT-SIGNATURE")
    if not payment_signature or payment_signature == "" then
      return payment_required_response()
    end

    local ok, settlement_or_error = pcall(settle_exact_payment, payment_signature)
    if not ok then
      return payment_error_response(settlement_or_error)
    end

    -- Canonical x402 v2 PAYMENT-RESPONSE header. Mirrors the Rust spine
    -- (rust/crates/x402/src/bin/interop_server.rs L221-231) and TS fixture
    -- (harness/src/fixtures/typescript/exact-server.ts L322-331). The
    -- header value is raw (non-base64) JSON carrying the canonical
    -- PaymentResponse fields: { success, network, transaction }. The
    -- fixture x-fixture-settlement header is preserved alongside because
    -- existing harness assertions rely on it.
    local network = read_env("X402_INTEROP_NETWORK", default_network)
    local payment_response = must_json_encode({
      success = true,
      network = network,
      transaction = settlement_or_error,
    }, "PAYMENT-RESPONSE")
    local response_headers = settlement_header_name .. ": " .. settlement_or_error ..
      "\r\nPAYMENT-RESPONSE: " .. payment_response .. "\r\n"
    return 200, "OK", response_headers, json_object({
      { "ok", true },
      { "paid", true },
      { "settlement", settlement_or_error }
    })
  else
    return 404, "Not Found", "", json_object({ { "error", "not_found" } })
  end
end

-- Introspection probe: when X402_INTEROP_LUA_PROBE=1 the server file exits
-- before binding a TCP socket and instead acts as a JSON-RPC-style verifier
-- driven from stdin. Each line is a JSON object describing one verifier
-- call; each response is a single line of JSON. Used by the runtime
-- adversarial tests in `tests/interop/test/lua-runtime.test.ts` to exercise
-- `verify_exact_transaction` against hand-crafted SVM payloads without
-- standing up the full HTTP server.
if os.getenv("X402_INTEROP_LUA_PROBE") == "1" then
  for line in io.lines() do
    local request = must_json_decode(line, "lua probe request")
    local response
    if request.op == "verify_exact_transaction" then
      local transaction = base64_decode(request.transaction_b64)
      if not transaction then
        response = { ok = false, error = "transaction decode failed" }
      else
        local ok, result = pcall(function()
          local parsed = parse_versioned_transaction(transaction)
          local transfer = verify_exact_transaction(parsed, request.requirement)
          return {
            destination = base58_encode(transfer.destination),
            mint = base58_encode(transfer.mint),
          }
        end)
        if ok then
          response = { ok = true, result = result }
        else
          response = { ok = false, error = tostring(result) }
        end
      end
    elseif request.op == "derive_ata" then
      local ok, result = pcall(function()
        return base58_encode(derive_associated_token_address(
          base58_decode(request.pay_to),
          base58_decode(request.token_program),
          base58_decode(request.mint),
          base58_decode(associated_token_program)
        ))
      end)
      if ok then
        response = { ok = true, ata = result }
      else
        response = { ok = false, error = tostring(result) }
      end
    elseif request.op == "on_curve" then
      local bytes = base64_decode(request.bytes_b64)
      response = { ok = true, on_curve = ed25519_on_curve(bytes) }
    else
      response = { ok = false, error = "unknown op" }
    end
    print(must_json_encode(response, "lua probe response"))
    io.stdout:flush()
  end
  os.exit(0)
end

-- Startup: load the facilitator keypair from
-- `X402_INTEROP_FACILITATOR_SECRET_KEY` (the same env var the Python, Go, and
-- PHP exact servers consume) and use its public key as the wire-level
-- `extra.feePayer`. Without this, the server would advertise the System
-- Program placeholder (11111…1111) — clients then build a transferChecked
-- targeting a fee-payer that cannot sign, and settlement fails on submit.
local function load_facilitator_keypair()
  local secret = os.getenv("X402_INTEROP_FACILITATOR_SECRET_KEY")
  if secret == nil or secret == "" then
    io.stderr:write(
      "x402_lua_interop_server_missing_facilitator_secret_key: " ..
      "set X402_INTEROP_FACILITATOR_SECRET_KEY to a 64-byte Solana secret " ..
      "key JSON array before starting the exact server\n"
    )
    os.exit(2)
  end

  local ok, keypair = pcall(keypair_from_json_secret, secret)
  if not ok then
    io.stderr:write(
      "x402_lua_interop_server_invalid_facilitator_secret_key: " ..
      tostring(keypair) .. "\n"
    )
    os.exit(2)
  end

  local derived_fee_payer = base58_encode(keypair.public_key)
  local advertised = os.getenv("X402_INTEROP_FEE_PAYER")
  if advertised ~= nil and advertised ~= "" and advertised ~= derived_fee_payer then
    io.stderr:write(
      "x402_lua_interop_server_fee_payer_mismatch: X402_INTEROP_FEE_PAYER=" ..
      advertised .. " does not match the public key derived from " ..
      "X402_INTEROP_FACILITATOR_SECRET_KEY (" .. derived_fee_payer .. ")\n"
    )
    os.exit(2)
  end

  loaded_facilitator_keypair = keypair
  default_fee_payer = derived_fee_payer
end

load_facilitator_keypair()

local server = assert(socket.bind("127.0.0.1", 0))
local _, port = server:getsockname()

print(json_object({
  { "type", "ready" },
  { "implementation", "lua" },
  { "role", "server" },
  { "port", port },
  { "capabilities", { "exact" } }
}))
io.stdout:flush()

while true do
  local client = server:accept()
  if client then
    local request_line = client:receive("*l") or ""
    local path = request_line:match("^%u+%s+([^%s]+)%s+HTTP/%d%.%d$") or "/"
    local headers = read_headers(client)
    local status, reason, extra_headers, body = response_for(path, headers)

    client:send(
      "HTTP/1.1 " .. status .. " " .. reason .. "\r\n" ..
      "content-type: application/json\r\n" ..
      extra_headers ..
      "content-length: " .. #body .. "\r\n" ..
      "connection: close\r\n\r\n" ..
      body
    )
    client:close()
  end
end
