#!/usr/bin/env luajit
-- Lua per-language adapter for the mpp-protocol conformance layer.
--
-- Speaks the canonical mpp-tools adapter ABI over stdin/stdout, identical to
-- the TypeScript reference runner at harness/src/protocol/runners/typescript.ts:
-- read one `{ "op": ..., "input": ... }` request as JSON on stdin and write one
--   { "success": true,  "result": ... }                         (happy path)
--   { "success": false, "error": ..., "error_type": ... }       (failure)
-- response as JSON on stdout. The spawn driver
-- (harness/src/protocol/runners/spawn.ts) wires this in exactly the same way
-- as every other language, via the harness/protocol-runners/lua.json manifest.
--
-- It calls the pay-kit Lua SDK's existing protocol-core functions per the
-- Reference operation map (lua/pay_kit/protocol/core/headers.lua + challenge.lua
-- + types.lua, lua/pay_kit/util/base64url.lua). All of those modules are pure
-- Lua and load under plain luajit without the native luasodium / cjson /
-- luasocket deps the live interop server needs.
--
-- ABI codec note: the SDK's pure-Lua util/json represents both `{}` and `[]`
-- as a bare empty table and re-emits an empty table as `[]`. The conformance
-- vectors carry empty *objects* (`request: {}`), and the canonical challenge-id
-- HMAC canonicalizes `{}` as `{}`. So this runner uses its OWN object/array-
-- aware JSON codec for the stdin envelope and the stdout response (tagging
-- object-typed tables), and feeds the SDK's challenge-id HMAC a correctly
-- canonicalized request slot. Everything else routes straight to the SDK.
--
-- Run directly:
--   echo '{"op":"base64url.encode","input":{"text":"a"}}' | luajit runner.lua
--
-- Conformance vs the canonical vectors (tempoxyz/mpp-tools): exact-match on all
-- base64url (20/20) and challenge-id HMAC (25/25); 82/90 cases overall. The
-- 8 gaps are genuine pay-kit Lua protocol-core divergences, NOT runner bugs,
-- and are reported as divergences rather than faked:
--   * challenge.format :: full_challenge — the SDK formatter intentionally
--     drops a top-level challenge `description` (headers.lua: "description is
--     already encoded inside the request payload; don't duplicate it"), so it
--     does not round-trip. challenge.parse DOES surface it.
--   * challenge.parse :: unescaped_quotes_in_description — the SDK's strict
--     RFC 7235 auth-param parser rejects an unescaped quote that mppx tolerates
--     (parses up to the first quote).
--   * credential.parse :: error_missing_challenge_id, and
--     receipt.parse :: error_missing_{status,method,reference,timestamp} +
--     error_non_iso8601_timestamp — the SDK parse_authorization / parse_receipt
--     base64url-decode + JSON-parse but do not schema-validate required fields
--     the way mppx (Zod) and the canonical spec do, so they accept these.

-- The manifest sets cwd to the repo root, so the Lua SDK lives under ./lua.
package.path = table.concat({
  './lua/?.lua',
  './lua/?/init.lua',
  './?.lua',
  './?/init.lua',
  package.path,
}, ';')

local headers = require('pay_kit.protocol.core.headers')
local challenge = require('pay_kit.protocol.core.challenge')
local types = require('pay_kit.protocol.core.types')

-- ── Object/array-aware JSON codec (runner-local) ──
--
-- Tables decoded (or built) as JSON objects carry an `OBJECT` marker in a weak
-- side table so the encoder can tell an empty object from an empty array, and
-- so RFC 8785 canonicalization of `{}` stays `{}`. Arrays are plain
-- 1..n tables.
local OBJECT = setmetatable({}, { __mode = 'k' })
local NULL = setmetatable({}, {}) -- JSON null sentinel
local function mark_object(t)
  OBJECT[t] = true
  return t
end

-- Decoder. Returns Lua values; objects are tagged via mark_object.
local J = {}
do
  local function decode_error(msg, pos)
    error('json: ' .. msg .. ' at ' .. tostring(pos))
  end
  local parse_value
  local function skip_ws(s, i)
    while i <= #s do
      local c = s:sub(i, i)
      if c == ' ' or c == '\t' or c == '\n' or c == '\r' then
        i = i + 1
      else
        break
      end
    end
    return i
  end
  local esc = { ['"'] = '"', ['\\'] = '\\', ['/'] = '/', b = '\b', f = '\f', n = '\n', r = '\r', t = '\t' }
  local function utf8_encode(cp)
    if cp < 0x80 then
      return string.char(cp)
    elseif cp < 0x800 then
      return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40)
    elseif cp < 0x10000 then
      return string.char(0xE0 + math.floor(cp / 0x1000), 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
    else
      return string.char(
        0xF0 + math.floor(cp / 0x40000),
        0x80 + math.floor(cp / 0x1000) % 0x40,
        0x80 + math.floor(cp / 0x40) % 0x40,
        0x80 + cp % 0x40
      )
    end
  end
  local function parse_string(s, i)
    i = i + 1 -- opening quote
    local out = {}
    while i <= #s do
      local c = s:sub(i, i)
      if c == '"' then
        return table.concat(out), i + 1
      elseif c == '\\' then
        local n = s:sub(i + 1, i + 1)
        if n == 'u' then
          local hex = s:sub(i + 2, i + 5)
          local cp = tonumber(hex, 16)
          if not cp then decode_error('bad \\u escape', i) end
          i = i + 6
          if cp >= 0xD800 and cp <= 0xDBFF then
            if s:sub(i, i + 1) == '\\u' then
              local lo = tonumber(s:sub(i + 2, i + 5), 16)
              if lo and lo >= 0xDC00 and lo <= 0xDFFF then
                cp = 0x10000 + (cp - 0xD800) * 0x400 + (lo - 0xDC00)
                i = i + 6
              end
            end
          end
          out[#out + 1] = utf8_encode(cp)
        else
          local r = esc[n]
          if not r then decode_error('bad escape', i) end
          out[#out + 1] = r
          i = i + 2
        end
      else
        out[#out + 1] = c
        i = i + 1
      end
    end
    decode_error('unterminated string', i)
  end
  local function parse_number(s, i)
    local j = i
    while j <= #s and s:sub(j, j):match('[%d%.eE%+%-]') do
      j = j + 1
    end
    local n = tonumber(s:sub(i, j - 1))
    if not n then decode_error('bad number', i) end
    return n, j
  end
  local function parse_array(s, i)
    i = skip_ws(s, i + 1)
    local out = {}
    if s:sub(i, i) == ']' then
      return out, i + 1
    end
    while true do
      local v
      v, i = parse_value(s, i)
      out[#out + 1] = v
      i = skip_ws(s, i)
      local c = s:sub(i, i)
      if c == ']' then
        return out, i + 1
      elseif c ~= ',' then
        decode_error('expected , or ]', i)
      end
      i = skip_ws(s, i + 1)
    end
  end
  local function parse_object(s, i)
    i = skip_ws(s, i + 1)
    local out = mark_object({})
    if s:sub(i, i) == '}' then
      return out, i + 1
    end
    while true do
      i = skip_ws(s, i)
      if s:sub(i, i) ~= '"' then decode_error('expected key string', i) end
      local key
      key, i = parse_string(s, i)
      i = skip_ws(s, i)
      if s:sub(i, i) ~= ':' then decode_error('expected :', i) end
      local v
      v, i = parse_value(s, i + 1)
      out[key] = v
      i = skip_ws(s, i)
      local c = s:sub(i, i)
      if c == '}' then
        return out, i + 1
      elseif c ~= ',' then
        decode_error('expected , or }', i)
      end
      i = i + 1
    end
  end
  function parse_value(s, i)
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == '"' then
      return parse_string(s, i)
    elseif c == '{' then
      return parse_object(s, i)
    elseif c == '[' then
      return parse_array(s, i)
    elseif c == 't' then
      if s:sub(i, i + 3) ~= 'true' then decode_error('bad literal', i) end
      return true, i + 4
    elseif c == 'f' then
      if s:sub(i, i + 4) ~= 'false' then decode_error('bad literal', i) end
      return false, i + 5
    elseif c == 'n' then
      if s:sub(i, i + 3) ~= 'null' then decode_error('bad literal', i) end
      return NULL, i + 4
    elseif c == '-' or c:match('%d') then
      return parse_number(s, i)
    end
    decode_error('unexpected token', i)
  end
  function J.decode(s)
    local v, i = parse_value(s, 1)
    i = skip_ws(s, i)
    if i <= #s then decode_error('trailing data', i) end
    return v
  end
end

-- Encoder. Object-tagged tables and explicitly object-shaped tables emit as
-- JSON objects with RFC 8785 (sorted-key) ordering; 1..n tables emit as arrays;
-- an *untagged* empty table emits as an empty object `{}` (the runner only
-- builds objects, never empty arrays, so this is the safe default).
do
  local encode_value
  local function is_array(t)
    local n = 0
    for k in pairs(t) do
      if type(k) ~= 'number' then
        return false
      end
      n = n + 1
    end
    if n == 0 then
      return false -- empty table => object, not array
    end
    for i = 1, n do
      if t[i] == nil then
        return false
      end
    end
    return true
  end
  local function encode_string(s)
    local out = s:gsub('[%z\1-\31\\"]', function(c)
      if c == '"' then return '\\"' end
      if c == '\\' then return '\\\\' end
      if c == '\b' then return '\\b' end
      if c == '\f' then return '\\f' end
      if c == '\n' then return '\\n' end
      if c == '\r' then return '\\r' end
      if c == '\t' then return '\\t' end
      return string.format('\\u%04x', c:byte())
    end)
    return '"' .. out .. '"'
  end
  encode_value = function(v)
    if v == NULL then
      return 'null'
    end
    local t = type(v)
    if t == 'nil' then
      return 'null'
    elseif t == 'boolean' then
      return v and 'true' or 'false'
    elseif t == 'number' then
      if v % 1 == 0 then
        return string.format('%d', v)
      end
      return tostring(v)
    elseif t == 'string' then
      return encode_string(v)
    elseif t == 'table' then
      if is_array(v) then
        local parts = {}
        for i = 1, #v do
          parts[i] = encode_value(v[i])
        end
        return '[' .. table.concat(parts, ',') .. ']'
      end
      local keys = {}
      for k in pairs(v) do
        keys[#keys + 1] = k
      end
      table.sort(keys)
      local parts = {}
      for _, k in ipairs(keys) do
        local ev = encode_value(v[k])
        if ev ~= nil then
          parts[#parts + 1] = encode_string(k) .. ':' .. ev
        end
      end
      return '{' .. table.concat(parts, ',') .. '}'
    end
    error('cannot encode ' .. t)
  end
  function J.encode(v)
    return encode_value(v)
  end
end

-- Treat a JSON null sentinel or absent value as "not provided".
local function present(value)
  if value == nil or value == NULL then
    return nil
  end
  return value
end

local function str(value)
  value = present(value)
  if value == nil then
    return nil
  end
  return tostring(value)
end

-- Base64url(JCS(request)) request slot. The SDK's compute_challenge_id and
-- header codec carry the request as this already-encoded string; the canonical
-- vectors carry it as a nested object. Use the runner's object-aware encoder so
-- an empty `{}` canonicalizes to `{}` (the SDK's own pure-Lua json would emit
-- `[]`).
local function request_slot(request)
  return types.base64url_encode(J.encode(present(request) or mark_object({})))
end

-- Decode a base64url(JSON) request slot back into a plain object so the parsed
-- shape matches the canonical golden object (request as a nested JSON object).
local function decode_request(raw)
  if raw == nil or raw == '' then
    return mark_object({})
  end
  local bytes, derr = types.base64url_decode(raw)
  if not bytes then
    error('invalid request field: ' .. tostring(derr))
  end
  return J.decode(bytes)
end

-- Build the canonical parsed-challenge object: required fields always present,
-- optional fields (description / expires / digest / opaque) only when present,
-- request decoded to an object. Mirrors what mppx's Challenge.deserialize
-- returns and what the canonical golden objects carry.
local function challenge_object(plain)
  local out = mark_object({
    id = plain.id,
    realm = plain.realm,
    method = plain.method,
    intent = plain.intent,
    request = decode_request(plain.request),
  })
  if plain.description and plain.description ~= '' then
    out.description = plain.description
  end
  if plain.expires and plain.expires ~= '' then
    out.expires = plain.expires
  end
  if plain.digest and plain.digest ~= '' then
    out.digest = plain.digest
  end
  if plain.opaque and plain.opaque ~= '' then
    out.opaque = plain.opaque
  end
  return out
end

-- Canonical challenge-id derivation, delegated to the SDK's
-- challenge.compute_challenge_id (the same HMAC the SDK's Challenge:verify
-- uses): HMAC-SHA256 over
--   realm|method|intent|base64url(JCS(request))|expires|digest|opaque
-- then unpadded base64url. `opaque` is the already-serialized pipe-slot string
-- (canonical challenge.id ABI); `description` is not part of the HMAC.
local function generate_challenge_id(input)
  return challenge.compute_challenge_id(
    input.secretKey,
    str(input.realm) or '',
    str(input.method) or '',
    str(input.intent) or '',
    request_slot(input.request),
    str(input.expires) or '',
    str(input.digest) or '',
    str(input.opaque) or ''
  )
end

local function header_of(input)
  return (input or {}).header
end

local function text_of(input)
  return (input or {}).text
end

-- Dispatch one ABI request. Returns the response table. Fallible SDK calls run
-- inside the top-level pcall in run(); a thrown Lua error becomes the right
-- error_type for the op, matching the TypeScript reference runner.
local function dispatch(op, input)
  if op == 'challenge.parse' then
    local value = headers.parse_www_authenticate(header_of(input))
    return { success = true, result = challenge_object(challenge.challenge_to_plain(value)) }
  elseif op == 'challenge.format' then
    local obj = input or {}
    local plain = {
      id = obj.id,
      realm = obj.realm,
      method = obj.method,
      intent = obj.intent,
      request = request_slot(obj.request),
      expires = str(obj.expires),
      description = str(obj.description),
      digest = str(obj.digest),
      opaque = str(obj.opaque),
    }
    local value = challenge.challenge_from_table(plain)
    return { success = true, result = mark_object({ header = headers.format_www_authenticate(value) }) }
  elseif op == 'credential.parse' then
    local value, err = headers.parse_authorization(header_of(input))
    if not value then
      error(tostring(err))
    end
    local plain = challenge.credential_to_plain(value)
    local out = mark_object({
      challenge = challenge_object(plain.challenge),
      payload = present(plain.payload),
    })
    if present(plain.source) ~= nil then
      out.source = plain.source
    end
    return { success = true, result = out }
  elseif op == 'credential.format' then
    local obj = input or {}
    local ch = obj.challenge or {}
    local credential = {
      challenge = challenge.challenge_from_table({
        id = ch.id,
        realm = ch.realm,
        method = ch.method,
        intent = ch.intent,
        request = request_slot(ch.request),
        expires = str(ch.expires),
        digest = str(ch.digest),
        opaque = str(ch.opaque),
      }),
      payload = present(obj.payload),
      source = present(obj.source),
    }
    return { success = true, result = mark_object({ header = headers.format_authorization(credential) }) }
  elseif op == 'receipt.parse' then
    local value = headers.parse_receipt(header_of(input))
    return { success = true, result = value }
  elseif op == 'receipt.format' then
    return { success = true, result = mark_object({ header = headers.format_receipt(input or {}) }) }
  elseif op == 'base64url.encode' then
    return { success = true, result = mark_object({ text = types.base64url_encode(text_of(input)) }) }
  elseif op == 'base64url.decode' then
    local bytes, derr = types.base64url_decode(text_of(input))
    if not bytes then
      error(tostring(derr))
    end
    return { success = true, result = mark_object({ text = bytes }) }
  elseif op == 'challenge.id' then
    return { success = true, result = mark_object({ id = generate_challenge_id(input or {}) }) }
  end
  return { success = false, error = 'Unknown operation: ' .. tostring(op), error_type = 'unsupported_operation' }
end

-- Map a thrown SDK error to the canonical error_type for the op, mirroring the
-- TypeScript reference runner's catch block.
local function error_type_for(op)
  if op:sub(-#'.parse') == '.parse' then
    return 'parse_error'
  elseif op:sub(-#'.format') == '.format' then
    return 'format_error'
  elseif op:sub(1, #'base64url.') == 'base64url.' then
    return 'encoding_error'
  elseif op == 'challenge.id' then
    return 'generation_error'
  end
  return 'unknown_error'
end

local function run()
  local raw = io.read('*a') or ''
  local decoded_ok, request = pcall(J.decode, raw)
  if not decoded_ok then
    io.write(J.encode(mark_object({
      success = false,
      error = 'invalid request JSON: ' .. tostring(request),
      error_type = 'unknown_error',
    })))
    return
  end
  local op = request.op
  local input = request.input
  local ok, response = pcall(dispatch, op, input)
  if not ok then
    io.write(J.encode(mark_object({
      success = false,
      error = tostring(response),
      error_type = error_type_for(tostring(op)),
    })))
    return
  end
  io.write(J.encode(mark_object(response)))
end

run()
