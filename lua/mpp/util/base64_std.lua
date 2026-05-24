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
--
-- Strict mode: matches Ruby's `Base64.strict_decode64` / PHP's
-- `base64_decode($input, true)`. Codex PR #103 review (P2) flagged
-- that the previous implementation accepted malformed strings with
-- internal `=` (e.g. `Zm=9`) or non-canonical trailing padding.
-- Reject any of:
--   * length not a multiple of 4
--   * `=` appearing anywhere except as canonical trailing padding
--     (at most two `=`, and only in the final quantum)
--   * non-alphabet bytes (including whitespace; the Solana wire payloads
--     never include whitespace)
--   * any base64 character whose low bits would produce trailing
--     non-zero bits beyond the encoded byte length
function M.decode(input)
  if input == nil or input == '' then
    return ''
  end
  if type(input) ~= 'string' then
    error('base64 input must be a string')
  end
  if #input % 4 ~= 0 then
    error('invalid base64 input: length is not a multiple of 4')
  end

  -- Validate every character before decoding. Padding (`=`) is only
  -- allowed in the last quantum (positions #input-1 and #input), and
  -- only as a contiguous trailing run of length 0, 1, or 2.
  local padding = 0
  if input:sub(-1) == '=' then
    padding = 1
    if input:sub(-2, -2) == '=' then
      padding = 2
    end
  end
  local content_len = #input - padding
  for i = 1, content_len do
    if DECODE[input:sub(i, i)] == nil then
      error('invalid base64 character at position ' .. tostring(i))
    end
  end
  -- Anything past content_len must be `=` (we already counted padding).
  for i = content_len + 1, #input do
    if input:sub(i, i) ~= '=' then
      error('invalid base64 padding at position ' .. tostring(i))
    end
  end

  local out = {}
  local i = 1
  while i <= content_len do
    local c1 = DECODE[input:sub(i, i)]
    local c2 = DECODE[input:sub(i + 1, i + 1)]
    local c3_char = input:sub(i + 2, i + 2)
    local c4_char = input:sub(i + 3, i + 3)
    local c3 = c3_char ~= '' and c3_char ~= '=' and DECODE[c3_char] or nil
    local c4 = c4_char ~= '' and c4_char ~= '=' and DECODE[c4_char] or nil
    -- Strictness: for a 2-byte final quantum (padding=2), the second
    -- character contributes only 4 low bits; the remaining 2 bits must
    -- be zero. For a 3-byte final quantum (padding=1), the third
    -- character contributes only 2 low bits; the remaining 4 bits must
    -- be zero. Reject otherwise so non-canonical encodings (e.g.
    -- `Ag==` valid but `Ah==` invalid) round-trip cleanly.
    if c3 == nil and c4 == nil then
      if c2 % 16 ~= 0 then
        error('invalid base64 trailing bits at position ' .. tostring(i))
      end
    elseif c4 == nil then
      if c3 % 4 ~= 0 then
        error('invalid base64 trailing bits at position ' .. tostring(i + 2))
      end
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
  return table.concat(out)
end

M.ALPHABET = ALPHABET

return M
