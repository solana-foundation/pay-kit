-- RFC 8785 canonical JSON encoder for the MPP Lua SDK.
--
-- @see https://datatracker.ietf.org/doc/html/rfc8785 RFC 8785 JSON Canonicalization Scheme
-- @see https://tc39.es/ecma262/multipage/abstract-operations.html#sec-numeric-types-number-tostring
--      ECMA-262 Number::toString algorithm (RFC 8785 sec 3.2.2.3 reference)
local M = {}

local null_sentinel = {}
M.null = null_sentinel

local function is_array(value)
  if type(value) ~= 'table' then
    return false
  end
  local max = 0
  local count = 0
  for k, _ in pairs(value) do
    if type(k) ~= 'number' or k < 1 or k % 1 ~= 0 then
      return false
    end
    if k > max then
      max = k
    end
    count = count + 1
  end
  return max == count
end

-- Decode a UTF-8 byte string into a list of codepoints.
-- Returns nil and error message for invalid UTF-8 or lone surrogates.
local function utf8_codepoints(value)
  local out = {}
  local i = 1
  local len = #value
  while i <= len do
    local b1 = value:byte(i)
    local cp
    local advance
    if b1 < 0x80 then
      cp = b1
      advance = 1
    elseif b1 < 0xC2 then
      return nil, 'invalid UTF-8 lead byte'
    elseif b1 < 0xE0 then
      if i + 1 > len then return nil, 'truncated UTF-8' end
      local b2 = value:byte(i + 1)
      if b2 < 0x80 or b2 >= 0xC0 then return nil, 'invalid UTF-8 continuation' end
      cp = (b1 - 0xC0) * 64 + (b2 - 0x80)
      advance = 2
    elseif b1 < 0xF0 then
      if i + 2 > len then return nil, 'truncated UTF-8' end
      local b2, b3 = value:byte(i + 1), value:byte(i + 2)
      if b2 < 0x80 or b2 >= 0xC0 or b3 < 0x80 or b3 >= 0xC0 then return nil, 'invalid UTF-8 continuation' end
      cp = (b1 - 0xE0) * 4096 + (b2 - 0x80) * 64 + (b3 - 0x80)
      if cp < 0x800 then return nil, 'overlong UTF-8 sequence' end
      if cp >= 0xD800 and cp <= 0xDFFF then return nil, 'lone surrogate' end
      advance = 3
    elseif b1 < 0xF5 then
      if i + 3 > len then return nil, 'truncated UTF-8' end
      local b2, b3, b4 = value:byte(i + 1), value:byte(i + 2), value:byte(i + 3)
      if b2 < 0x80 or b2 >= 0xC0 or b3 < 0x80 or b3 >= 0xC0 or b4 < 0x80 or b4 >= 0xC0 then return nil, 'invalid UTF-8 continuation' end
      cp = (b1 - 0xF0) * 262144 + (b2 - 0x80) * 4096 + (b3 - 0x80) * 64 + (b4 - 0x80)
      if cp < 0x10000 then return nil, 'overlong UTF-8 sequence' end
      -- Reject codepoints above U+10FFFF (max valid Unicode, RFC 3629 sec 3).
      -- 0xF4 lead with continuation > 0x8F encodes >= U+110000.
      if cp > 0x10FFFF then return nil, 'UTF-8 codepoint out of range' end
      advance = 4
    else
      return nil, 'invalid UTF-8 lead byte'
    end
    out[#out + 1] = cp
    i = i + advance
  end
  return out
end

local function encode_string(value)
  local cps, err = utf8_codepoints(value)
  if not cps then
    error('cannot encode string: ' .. err)
  end
  local buf = { '"' }
  for _, cp in ipairs(cps) do
    if cp == 0x5C then
      buf[#buf + 1] = '\\\\'
    elseif cp == 0x22 then
      buf[#buf + 1] = '\\"'
    elseif cp == 0x08 then
      buf[#buf + 1] = '\\b'
    elseif cp == 0x09 then
      buf[#buf + 1] = '\\t'
    elseif cp == 0x0A then
      buf[#buf + 1] = '\\n'
    elseif cp == 0x0C then
      buf[#buf + 1] = '\\f'
    elseif cp == 0x0D then
      buf[#buf + 1] = '\\r'
    elseif cp < 0x20 then
      buf[#buf + 1] = string.format('\\u%04x', cp)
    elseif cp < 0x80 then
      buf[#buf + 1] = string.char(cp)
    elseif cp < 0x800 then
      buf[#buf + 1] = string.char(0xC0 + math.floor(cp / 64), 0x80 + (cp % 64))
    elseif cp < 0x10000 then
      buf[#buf + 1] = string.char(
        0xE0 + math.floor(cp / 4096),
        0x80 + math.floor(cp / 64) % 64,
        0x80 + (cp % 64)
      )
    else
      buf[#buf + 1] = string.char(
        0xF0 + math.floor(cp / 262144),
        0x80 + math.floor(cp / 4096) % 64,
        0x80 + math.floor(cp / 64) % 64,
        0x80 + (cp % 64)
      )
    end
  end
  buf[#buf + 1] = '"'
  return table.concat(buf)
end

-- UTF-16 code-unit comparison for JCS key ordering (RFC 8785 sec 3.2.3).
local function utf16_units(value)
  local cps, err = utf8_codepoints(value)
  if not cps then
    error('cannot order key: ' .. err)
  end
  local units = {}
  for _, cp in ipairs(cps) do
    if cp < 0x10000 then
      units[#units + 1] = cp
    else
      local off = cp - 0x10000
      units[#units + 1] = 0xD800 + math.floor(off / 1024)
      units[#units + 1] = 0xDC00 + (off % 1024)
    end
  end
  return units
end

local function compare_utf16(a, b)
  local au = utf16_units(a)
  local bu = utf16_units(b)
  local n = math.min(#au, #bu)
  for i = 1, n do
    if au[i] ~= bu[i] then
      return au[i] < bu[i]
    end
  end
  return #au < #bu
end

-- Render digits + decimal exponent k as ES6 ToString (ECMA-262 7.1.12.1).
local function format_es6_number(sign, digits, k)
  local n = #digits
  if k >= 0 and k <= 20 then
    if n <= k + 1 then
      return sign .. digits .. string.rep('0', k + 1 - n)
    end
    return sign .. digits:sub(1, k + 1) .. '.' .. digits:sub(k + 2)
  end
  if k < 0 and k > -7 then
    return sign .. '0.' .. string.rep('0', -k - 1) .. digits
  end
  local mantissa = n == 1 and digits or (digits:sub(1, 1) .. '.' .. digits:sub(2))
  local exp_sign = k >= 0 and '+' or '-'
  return sign .. mantissa .. 'e' .. exp_sign .. math.abs(k)
end

-- Return digits, k (decimal exponent of leading digit) for the shortest round-trip decimal of abs(value).
-- Walks %.{p}g from p=1..17 to find the shortest representation that round-trips to the same double,
-- per ES6 ToString (ECMA-262 7.1.12.1). Stopping at %.15g and falling back to %.17g misses values
-- whose shortest form requires exactly 16 significant digits (e.g. 333333333.33333329).
local function shortest_digits_and_exponent(abs_value)
  local repr = string.format('%.17g', abs_value)
  for p = 1, 17 do
    local candidate = string.format('%.' .. p .. 'g', abs_value)
    if tonumber(candidate) == abs_value then
      repr = candidate
      break
    end
  end
  local mantissa, exp_str
  local e_idx = repr:find('[eE]')
  if e_idx then
    mantissa = repr:sub(1, e_idx - 1)
    exp_str = repr:sub(e_idx + 1)
  else
    mantissa = repr
    exp_str = '0'
  end
  local exp_int = tonumber(exp_str)
  local dot_pos = mantissa:find('%.', 1, false)
  local int_part, frac_part
  if dot_pos then
    int_part = mantissa:sub(1, dot_pos - 1)
    frac_part = mantissa:sub(dot_pos + 1)
  else
    int_part = mantissa
    frac_part = ''
  end
  local combined = int_part .. frac_part
  local stripped = combined:gsub('^0+', '')
  local leading_zeros = #combined - #stripped
  local digits = stripped:gsub('0+$', '')
  if digits == '' then
    digits = '0'
  end
  local decimal_exponent = exp_int + #int_part - 1 - leading_zeros
  return digits, decimal_exponent
end

-- ES6 ToString number serialization (ECMA-262 7.1.12.1) for JCS (RFC 8785 sec 3.2.2.3).
local function encode_number(value)
  if value ~= value or value == math.huge or value == -math.huge then
    error('cannot encode non-finite number')
  end
  if value == 0 then
    return '0'
  end
  local sign = value < 0 and '-' or ''
  local digits, k = shortest_digits_and_exponent(math.abs(value))
  return format_es6_number(sign, digits, k)
end

local function encode_value(value)
  local kind = type(value)
  if value == null_sentinel then
    return 'null'
  elseif kind == 'nil' then
    return 'null'
  elseif kind == 'boolean' then
    return value and 'true' or 'false'
  elseif kind == 'number' then
    return encode_number(value)
  elseif kind == 'string' then
    return encode_string(value)
  elseif kind == 'table' then
    if is_array(value) then
      local parts = {}
      for i = 1, #value do
        parts[#parts + 1] = encode_value(value[i])
      end
      return '[' .. table.concat(parts, ',') .. ']'
    end
    local keys = {}
    for key, _ in pairs(value) do
      keys[#keys + 1] = key
    end
    table.sort(keys, compare_utf16)
    local parts = {}
    for i = 1, #keys do
      local key = keys[i]
      local encoded = encode_value(value[key])
      if encoded ~= nil then
        parts[#parts + 1] = encode_string(key) .. ':' .. encoded
      end
    end
    return '{' .. table.concat(parts, ',') .. '}'
  end
  error('unsupported JSON type: ' .. kind)
end

function M.encode(value)
  return encode_value(value)
end

local Parser = {}
Parser.__index = Parser

function Parser:new(input)
  return setmetatable({ input = input, pos = 1, len = #input }, self)
end

function Parser:peek()
  return self.input:sub(self.pos, self.pos)
end

function Parser:next()
  local ch = self:peek()
  self.pos = self.pos + 1
  return ch
end

function Parser:skip_ws()
  while self.pos <= self.len do
    local ch = self:peek()
    if ch == ' ' or ch == '\n' or ch == '\r' or ch == '\t' then
      self.pos = self.pos + 1
    else
      break
    end
  end
end

function Parser:expect(text)
  if self.input:sub(self.pos, self.pos + #text - 1) ~= text then
    error('expected ' .. text .. ' at position ' .. self.pos)
  end
  self.pos = self.pos + #text
end

function Parser:parse_string()
  self:expect('"')
  local out = {}
  while self.pos <= self.len do
    local ch = self:next()
    if ch == '"' then
      return table.concat(out)
    elseif ch == '\\' then
      local esc = self:next()
      if esc == '"' or esc == '\\' or esc == '/' then
        out[#out + 1] = esc
      elseif esc == 'b' then
        out[#out + 1] = '\b'
      elseif esc == 'f' then
        out[#out + 1] = '\f'
      elseif esc == 'n' then
        out[#out + 1] = '\n'
      elseif esc == 'r' then
        out[#out + 1] = '\r'
      elseif esc == 't' then
        out[#out + 1] = '\t'
      elseif esc == 'u' then
        local hex = self.input:sub(self.pos, self.pos + 3)
        if #hex ~= 4 or not hex:match('^[0-9a-fA-F]+$') then
          error('invalid unicode escape at position ' .. self.pos)
        end
        self.pos = self.pos + 4
        local code = tonumber(hex, 16)
        if code < 128 then
          out[#out + 1] = string.char(code)
        elseif code < 2048 then
          out[#out + 1] = string.char(192 + math.floor(code / 64), 128 + (code % 64))
        else
          out[#out + 1] = string.char(
            224 + math.floor(code / 4096),
            128 + (math.floor(code / 64) % 64),
            128 + (code % 64)
          )
        end
      else
        error('invalid escape character at position ' .. self.pos)
      end
    else
      out[#out + 1] = ch
    end
  end
  error('unterminated string')
end

function Parser:parse_number()
  local start = self.pos
  local allowed = '[0-9+%-eE%.]'
  while self.pos <= self.len and self:peek():match(allowed) do
    self.pos = self.pos + 1
  end
  local text = self.input:sub(start, self.pos - 1)
  local value = tonumber(text)
  if value == nil then
    error('invalid number at position ' .. start)
  end
  return value
end

function Parser:parse_array()
  self:expect('[')
  self:skip_ws()
  local out = {}
  if self:peek() == ']' then
    self.pos = self.pos + 1
    return out
  end
  while true do
    out[#out + 1] = self:parse_value()
    self:skip_ws()
    local ch = self:next()
    if ch == ']' then
      return out
    elseif ch ~= ',' then
      error('expected , or ] at position ' .. self.pos)
    end
    self:skip_ws()
  end
end

function Parser:parse_object()
  self:expect('{')
  self:skip_ws()
  local out = {}
  if self:peek() == '}' then
    self.pos = self.pos + 1
    return out
  end
  while true do
    local key = self:parse_string()
    self:skip_ws()
    self:expect(':')
    self:skip_ws()
    out[key] = self:parse_value()
    self:skip_ws()
    local ch = self:next()
    if ch == '}' then
      return out
    elseif ch ~= ',' then
      error('expected , or } at position ' .. self.pos)
    end
    self:skip_ws()
  end
end

function Parser:parse_value()
  self:skip_ws()
  local ch = self:peek()
  if ch == '"' then
    return self:parse_string()
  elseif ch == '{' then
    return self:parse_object()
  elseif ch == '[' then
    return self:parse_array()
  elseif ch == '-' or ch:match('%d') then
    return self:parse_number()
  elseif ch == 't' then
    self:expect('true')
    return true
  elseif ch == 'f' then
    self:expect('false')
    return false
  elseif ch == 'n' then
    self:expect('null')
    return null_sentinel
  end
  error('unexpected token at position ' .. self.pos)
end

function M.decode(input)
  local parser = Parser:new(input)
  local value = parser:parse_value()
  parser:skip_ws()
  if parser.pos <= parser.len then
    error('unexpected trailing input at position ' .. parser.pos)
  end
  return value
end

return M
