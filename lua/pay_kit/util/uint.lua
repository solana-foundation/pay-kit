local M = {}

local function normalize(value)
  local text = tostring(value or "")
  if not text:match("^%d+$") then
    error("invalid unsigned integer: " .. text)
  end
  text = text:gsub("^0+", "")
  if text == "" then
    return "0"
  end
  return text
end

function M.normalize(value)
  return normalize(value)
end

-- Coerce an on-chain amount to an EXACT decimal string, rejecting any Lua
-- number that cannot represent the value losslessly.
--
-- M1: the jsonParsed RPC path (getTransaction encoding=jsonParsed) decodes a
-- u64 lamports / token amount as a Lua number. On LuaJIT / Lua 5.1 every JSON
-- number is a double (53-bit mantissa), so a value >= 2^53 is BOTH lossy AND
-- serializes through tostring() as scientific notation (e.g. "9e+18"), which
-- normalize() then rejects with a confusing "invalid unsigned integer". A
-- silently-truncated amount that DID normalize would be worse: it would let a
-- transfer of the wrong lamports satisfy the amount check. Reject a float that
-- is non-integral, out of the safely-representable range (|x| > 2^53), or
-- infinite/NaN, so only exact integers reach the comparison. A string source
-- (the safe raw-bytes decode in solana/instructions.lua, and the challenge
-- amounts which are always strings) passes straight through to normalize().
local MAX_EXACT_DOUBLE = 9007199254740992 -- 2^53

function M.exact(value)
  if type(value) == "number" then
    -- Reject NaN (value ~= value), +/-inf, and any non-integral double.
    if value ~= value or value == math.huge or value == -math.huge then
      error("amount is not an exact integer: " .. tostring(value))
    end
    if value < 0 then
      error("amount is negative: " .. tostring(value))
    end
    -- math.floor keeps the double whole-valued; a fractional part means the
    -- source was not an integer amount.
    if math.floor(value) ~= value then
      error("amount is not an exact integer: " .. tostring(value))
    end
    -- Above 2^53 a double can no longer represent every integer, so the
    -- value may already be lossy. Refuse rather than compare a corrupted
    -- amount. Exact-source callers pass a string and never hit this.
    if value > MAX_EXACT_DOUBLE then
      error("amount exceeds exact-integer range for a Lua number: " .. tostring(value))
    end
    return string.format("%.0f", value)
  end
  return normalize(value)
end

function M.compare(left, right)
  left = normalize(left)
  right = normalize(right)
  if #left < #right then
    return -1
  elseif #left > #right then
    return 1
  end
  if left < right then
    return -1
  elseif left > right then
    return 1
  end
  return 0
end

function M.add(left, right)
  left = normalize(left)
  right = normalize(right)
  local i = #left
  local j = #right
  local carry = 0
  local out = {}

  while i > 0 or j > 0 or carry > 0 do
    local a = i > 0 and tonumber(left:sub(i, i)) or 0
    local b = j > 0 and tonumber(right:sub(j, j)) or 0
    local sum = a + b + carry
    out[#out + 1] = tostring(sum % 10)
    carry = math.floor(sum / 10)
    i = i - 1
    j = j - 1
  end

  local chars = {}
  for idx = #out, 1, -1 do
    chars[#chars + 1] = out[idx]
  end
  return table.concat(chars)
end

function M.sub(left, right)
  left = normalize(left)
  right = normalize(right)
  if M.compare(left, right) < 0 then
    error("unsigned subtraction underflow")
  end
  local i = #left
  local j = #right
  local borrow = 0
  local out = {}

  while i > 0 do
    local a = tonumber(left:sub(i, i)) - borrow
    local b = j > 0 and tonumber(right:sub(j, j)) or 0
    if a < b then
      a = a + 10
      borrow = 1
    else
      borrow = 0
    end
    out[#out + 1] = tostring(a - b)
    i = i - 1
    j = j - 1
  end

  local chars = {}
  for idx = #out, 1, -1 do
    chars[#chars + 1] = out[idx]
  end
  local value = table.concat(chars):gsub("^0+", "")
  if value == "" then
    return "0"
  end
  return value
end

return M
