local challenge = require('pay_kit.protocol.core.challenge')
local types = require('pay_kit.protocol.core.types')
local json = require('pay_kit.util.json')
local expires = require('pay_kit.protocols.mpp.expires')

local M = {
  WWW_AUTHENTICATE_HEADER = 'www-authenticate',
  AUTHORIZATION_HEADER = 'authorization',
  PAYMENT_RECEIPT_HEADER = 'payment-receipt',
  PAYMENT_SCHEME = 'Payment',
}

local max_token_len = 16 * 1024

local function escape_quoted(value)
  value = tostring(value)
  -- RFC 9110 section 5.5 forbids CR and LF in header field values. Silent
  -- strip is non-conformant and lets malformed inputs round-trip; reject
  -- so the caller sees the problem at emission time.
  if value:find('[\r\n]') then
    error('control character in header parameter value')
  end
  value = value:gsub('\\', '\\\\'):gsub('"', '\\"')
  return value
end

local function strip_payment_scheme(header)
  local trimmed = header:gsub('^%s+', '')
  if trimmed:sub(1, #M.PAYMENT_SCHEME):lower() ~= string.lower(M.PAYMENT_SCHEME) then
    return nil
  end
  return trimmed:sub(#M.PAYMENT_SCHEME + 1):gsub('^%s+', '')
end

local function parse_auth_params(input)
  local params = {}
  local i = 1
  while i <= #input do
    while i <= #input and input:sub(i, i):match('[%s,]') do
      i = i + 1
    end
    if i > #input then
      break
    end
    local eq = input:find('=', i, true)
    if not eq then
      error('invalid auth parameter')
    end
    local key = input:sub(i, eq - 1):gsub('%s+$', '')
    i = eq + 1
    local value
    if input:sub(i, i) == '"' then
      i = i + 1
      local out = {}
      local escaped = false
      while i <= #input do
        local ch = input:sub(i, i)
        i = i + 1
        if escaped then
          out[#out + 1] = ch
          escaped = false
        elseif ch == '\\' then
          escaped = true
        elseif ch == '"' then
          break
        else
          out[#out + 1] = ch
        end
      end
      value = table.concat(out)
      -- Permissive RFC 7235 quoted-string handling, matching the canonical
      -- mpp-tools parser: any text between a closing quote and the next
      -- comma (e.g. an unescaped inner quote that prematurely closed the
      -- value) is ignored rather than treated as a malformed parameter.
      local next_comma = input:find(',', i, true)
      if next_comma then
        i = next_comma + 1
      else
        i = #input + 1
      end
    else
      local next_comma = input:find(',', i, true)
      if next_comma then
        value = input:sub(i, next_comma - 1):gsub('%s+$', '')
        i = next_comma + 1
      else
        value = input:sub(i):gsub('%s+$', '')
        i = #input + 1
      end
    end
    if params[key] ~= nil then
      error('duplicate parameter: ' .. key)
    end
    params[key] = value
  end
  return params
end

-- RFC 7230 sec 3.2.6 tchar.
local TCHAR_EXTRA = "!#$%%&'*+-.^_`|~"
local function token_char(ch)
  if ch == '' then return false end
  if ch:match('[%w]') then return true end
  return TCHAR_EXTRA:find(ch, 1, true) ~= nil
end

-- If `header[pos]` starts an auth-scheme (RFC 7235 sec 2.1), return
-- offset_after_scheme, is_payment_scheme. Otherwise return nil.
--
-- A scheme requires: token, 1*SP, then non-empty content (either auth-param
-- list `key=val,...` or a token68 credential). A bare `token=` (no SP gap)
-- is an auth-param continuation, not a new scheme.
local function match_auth_scheme_start(header, pos, len, payment_scheme_lower)
  local token_end = pos
  while token_end <= len and token_char(header:sub(token_end, token_end)) do
    token_end = token_end + 1
  end
  if token_end == pos then return nil end
  local after_token = header:sub(token_end, token_end)
  if after_token ~= ' ' and after_token ~= '\t' then return nil end
  local cursor = token_end
  while cursor <= len do
    local c = header:sub(cursor, cursor)
    if c ~= ' ' and c ~= '\t' then break end
    cursor = cursor + 1
  end
  if cursor > len then return nil end
  -- Must have non-empty content (not just trailing whitespace or a comma).
  local c0 = header:sub(cursor, cursor)
  if c0 == ',' then return nil end
  local scheme = header:sub(pos, token_end - 1):lower()
  return token_end, scheme == payment_scheme_lower
end

-- Quote-aware split of a WWW-Authenticate header value into individual `Payment` chunks (RFC 7235 sec 4.1).
--
-- Detects auth-scheme boundaries (token + SP + key=value), not just literal "Payment"
-- occurrences, so trailing or interleaving non-Payment schemes (e.g. Bearer) correctly
-- terminate the previous Payment chunk.
local function split_payment_challenge_values(header)
  local len = #header
  local scheme_starts = {} -- list of {offset, is_payment}
  local in_quote = false
  local escaped = false
  local at_boundary = true
  local i = 1
  local payment_scheme_lower = M.PAYMENT_SCHEME:lower()

  while i <= len do
    local ch = header:sub(i, i)
    if in_quote then
      if escaped then
        escaped = false
      elseif ch == '\\' then
        escaped = true
      elseif ch == '"' then
        in_quote = false
      end
      i = i + 1
    elseif ch == '"' then
      in_quote = true
      at_boundary = false
      i = i + 1
    elseif ch == ',' then
      at_boundary = true
      i = i + 1
    elseif ch == ' ' or ch == '\t' then
      i = i + 1
    elseif at_boundary and token_char(ch) then
      local scheme_end, is_payment = match_auth_scheme_start(header, i, len, payment_scheme_lower)
      if scheme_end then
        scheme_starts[#scheme_starts + 1] = { i, is_payment }
        i = scheme_end
        at_boundary = false
      else
        at_boundary = false
        i = i + 1
      end
    else
      at_boundary = false
      i = i + 1
    end
  end

  if #scheme_starts == 0 then
    return {}
  end

  local chunks = {}
  for idx, entry in ipairs(scheme_starts) do
    local start, is_payment = entry[1], entry[2]
    if is_payment then
      local finish = scheme_starts[idx + 1] and (scheme_starts[idx + 1][1] - 1) or len
      local chunk = header:sub(start, finish):gsub('^%s+', ''):gsub('%s+$', '')
      chunk = chunk:gsub(',%s*$', '')
      if chunk ~= '' then
        chunks[#chunks + 1] = chunk
      end
    end
  end
  return chunks
end

function M.split_payment_challenge_values(header)
  return split_payment_challenge_values(header)
end

function M.extract_payment_scheme(header)
  local chunks = split_payment_challenge_values(header)
  return chunks[1]
end

-- Parse all `Payment` challenges across one or more WWW-Authenticate values (RFC 7235 sec 4.1).
-- Returns only successfully-parsed challenges; malformed individual challenges are skipped, mirroring
-- the Rust spine which exposes Vec<Result<PaymentChallenge, Error>> and filters at the call site.
function M.parse_www_authenticate_all(headers)
  local list = type(headers) == 'string' and { headers } or headers
  local results = {}
  for _, h in ipairs(list) do
    for _, chunk in ipairs(split_payment_challenge_values(h)) do
      local ok, value = pcall(M.parse_www_authenticate, chunk)
      if ok then
        results[#results + 1] = value
      end
    end
  end
  return results
end

function M.parse_www_authenticate(header)
  local rest = strip_payment_scheme(header)
  if not rest then
    error('expected "Payment" scheme')
  end
  local params = parse_auth_params(rest)
  if not params.request or params.request == '' then
    error('missing "request" field')
  end
  local request_bytes, decode_err = types.base64url_decode(params.request)
  if not request_bytes then
    error('invalid request field: ' .. decode_err)
  end
  local ok = pcall(json.decode, request_bytes)
  if not ok then
    error('invalid JSON in request field')
  end
  local method = types.new_method_name(params.method or '')
  if not types.is_valid_method(method) then
    error('invalid method: ' .. tostring(params.method))
  end
  if not params.id or params.id == '' or not params.realm or params.realm == '' or not params.intent or params.intent == '' then
    error('missing required challenge fields')
  end
  return challenge.challenge_from_table({
    id = params.id,
    realm = params.realm,
    method = method,
    intent = types.new_intent_name(params.intent),
    request = params.request,
    expires = params.expires,
    description = params.description,
    digest = params.digest,
    opaque = params.opaque,
  })
end

function M.format_www_authenticate(value)
  local plain = challenge.challenge_to_plain(value)
  local parts = {
    'id="' .. escape_quoted(plain.id) .. '"',
    'realm="' .. escape_quoted(plain.realm) .. '"',
    'method="' .. escape_quoted(plain.method) .. '"',
    'intent="' .. escape_quoted(plain.intent) .. '"',
    'request="' .. escape_quoted(plain.request) .. '"',
  }
  -- Emit optional params in the canonical mpp-tools wire order
  -- (description before digest/expires). The canonical golden requires
  -- `description` to round-trip as a first-class WWW-Authenticate parameter,
  -- so it is emitted here even though it is also carried inside the request
  -- payload and is excluded from the challenge-id HMAC.
  if plain.description and plain.description ~= '' then
    parts[#parts + 1] = 'description="' .. escape_quoted(plain.description) .. '"'
  end
  if plain.expires and plain.expires ~= '' then
    parts[#parts + 1] = 'expires="' .. escape_quoted(plain.expires) .. '"'
  end
  if plain.digest and plain.digest ~= '' then
    parts[#parts + 1] = 'digest="' .. escape_quoted(plain.digest) .. '"'
  end
  if plain.opaque and plain.opaque ~= '' then
    parts[#parts + 1] = 'opaque="' .. escape_quoted(plain.opaque) .. '"'
  end
  return M.PAYMENT_SCHEME .. ' ' .. table.concat(parts, ', ')
end

-- parse_authorization returns `(value, nil)` on success and `(nil, err)` on
-- any malformed input (missing scheme, oversize token, bad base64url,
-- invalid JSON, malformed inner challenge). Callers across the SDK
-- (`examples/simple-server.lua`, the Kong plugin handler, the harness
-- harness) already use the `(value, err)` shape; the previous
-- `error(...)` exits surfaced to those callers as 500-style unwinds
-- instead of structured 402 responses, which codex PR #103 review
-- flagged as P2. Internally protect every fallible step with pcall.
function M.parse_authorization(header)
  local token = M.extract_payment_scheme(header)
  if not token then
    return nil, 'expected "Payment" scheme'
  end
  token = token:sub(#M.PAYMENT_SCHEME + 1):gsub('^%s+', '')
  if #token > max_token_len then
    return nil, 'token exceeds maximum length of ' .. max_token_len .. ' bytes'
  end
  local payload, decode_err = types.base64url_decode(token)
  if not payload then
    return nil, decode_err
  end
  local json_ok, value = pcall(json.decode, payload)
  if not json_ok then
    return nil, 'invalid credential JSON: ' .. tostring(value)
  end
  if type(value) ~= 'table' then
    return nil, 'credential payload must be a JSON object'
  end
  -- The canonical mpp-tools spec rejects a credential whose embedded
  -- challenge is absent or carries no `id`. Validate the nested challenge
  -- shape before constructing it so malformed credentials surface as a
  -- structured parse error rather than being accepted.
  if type(value.challenge) ~= 'table' then
    return nil, 'credential challenge must be a JSON object'
  end
  if not value.challenge.id or value.challenge.id == '' then
    return nil, 'credential challenge missing required "id" field'
  end
  local challenge_ok, challenge_value = pcall(challenge.challenge_from_table, value.challenge)
  if not challenge_ok then
    return nil, 'invalid credential challenge: ' .. tostring(challenge_value)
  end
  value.challenge = challenge_value
  return value
end

function M.format_authorization(value)
  local payload = json.encode(challenge.credential_to_plain(value))
  return M.PAYMENT_SCHEME .. ' ' .. types.base64url_encode(payload)
end

function M.parse_receipt(header)
  if #header > max_token_len then
    error('receipt exceeds maximum length of ' .. max_token_len .. ' bytes')
  end
  local payload, decode_err = types.base64url_decode((header:gsub('^%s+', ''):gsub('%s+$', '')))
  if not payload then
    error(decode_err)
  end
  local ok, value = pcall(json.decode, payload)
  if not ok then
    error('invalid receipt JSON: ' .. value)
  end
  if type(value) ~= 'table' then
    error('receipt payload must be a JSON object')
  end
  -- The canonical mpp-tools spec rejects a receipt that omits any required
  -- field (status / method / reference / timestamp) and one whose timestamp
  -- is not an ISO-8601 (RFC 3339) instant.
  for _, field in ipairs({ 'status', 'method', 'reference', 'timestamp' }) do
    if value[field] == nil or value[field] == '' then
      error('receipt missing required "' .. field .. '" field')
    end
  end
  if not expires.parse_rfc3339(value.timestamp) then
    error('receipt timestamp is not a valid ISO-8601 instant: ' .. tostring(value.timestamp))
  end
  return value
end

function M.format_receipt(value)
  return types.base64url_encode(json.encode(challenge.receipt_to_plain(value)))
end

return M
