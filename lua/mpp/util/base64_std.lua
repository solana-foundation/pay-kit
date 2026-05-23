--[[
Standard padded Base64 codec.

Separate from `mpp.util.base64url` because the Solana JSON-RPC wire format
uses the standard alphabet with '+', '/' and '=' padding for the
`sendTransaction` and `getTransaction` payloads. The existing base64url
helper strips padding and substitutes the URL-safe alphabet, which would
corrupt those payloads.
]]

local M = {}

local ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local DECODE = {}
for i = 1, #ALPHABET do
  DECODE[ALPHABET:sub(i, i)] = i - 1
end

--- Encode binary bytes as a standard padded Base64 string.
function M.encode(input)
  if input == nil or input == '' then
    return ''
  end
  local out = {}
  local i = 1
  while i <= #input do
    local a = input:byte(i)
    local b = input:byte(i + 1)
    local c = input:byte(i + 2)
    local triple = a * 65536 + (b or 0) * 256 + (c or 0)
    out[#out + 1] = ALPHABET:sub(math.floor(triple / 262144) + 1, math.floor(triple / 262144) + 1)
    out[#out + 1] = ALPHABET:sub((math.floor(triple / 4096) % 64) + 1, (math.floor(triple / 4096) % 64) + 1)
    if b ~= nil then
      out[#out + 1] = ALPHABET:sub((math.floor(triple / 64) % 64) + 1, (math.floor(triple / 64) % 64) + 1)
    else
      out[#out + 1] = '='
    end
    if c ~= nil then
      out[#out + 1] = ALPHABET:sub((triple % 64) + 1, (triple % 64) + 1)
    else
      out[#out + 1] = '='
    end
    i = i + 3
  end
  return table.concat(out)
end

--- Decode a standard padded Base64 string into binary bytes.
function M.decode(input)
  if input == nil or input == '' then
    return ''
  end
  -- Strip whitespace; the wire format does not introduce any but defensive
  -- code helps when the value is copy-pasted into a test fixture.
  local cleaned = input:gsub('%s', '')
  -- Drop trailing padding before processing; treat it as length information
  -- rather than as a special character.
  local padding = 0
  while cleaned:sub(-1) == '=' do
    cleaned = cleaned:sub(1, -2)
    padding = padding + 1
  end
  local out = {}
  local i = 1
  while i <= #cleaned do
    local c1 = DECODE[cleaned:sub(i, i)]
    local c2 = DECODE[cleaned:sub(i + 1, i + 1)]
    local c3 = DECODE[cleaned:sub(i + 2, i + 2)]
    local c4 = DECODE[cleaned:sub(i + 3, i + 3)]
    if c1 == nil or c2 == nil then
      error('invalid base64 input at position ' .. tostring(i))
    end
    local triple = c1 * 262144 + c2 * 4096 + (c3 or 0) * 64 + (c4 or 0)
    out[#out + 1] = string.char(math.floor(triple / 65536) % 256)
    if c3 ~= nil then
      out[#out + 1] = string.char(math.floor(triple / 256) % 256)
    end
    if c4 ~= nil then
      out[#out + 1] = string.char(triple % 256)
    end
    i = i + 4
  end
  -- The decode loop already emits only the bytes that the input carries
  -- (it skips the second and third byte when c3 / c4 are nil after the
  -- trailing padding has been stripped). The captured `padding` count is
  -- kept around in case a future caller wants to assert canonical padding,
  -- but it is not used to truncate the output.
  local _ = padding
  return table.concat(out)
end

M.ALPHABET = ALPHABET

return M
