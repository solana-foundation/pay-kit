--[[
Signer factory family.

Mirrors `PayKit::Signer` in the Ruby SDK and the design's "Signer
backends" section. Local signers (synchronous, no I/O on :sign) ship
in v1; remote KMS-backed signers (cosocket I/O on :sign) live under
`pay_kit.kms` and are reserved for post-v1.

Every factory returns a signer table satisfying the duck type:

  {
    pubkey    = function(self) return "<base58 string>" end,
    sign      = function(self, message) return "<64-byte signature>", err end,
    fee_payer = function(self) return true end,
    demo      = function(self) return false end,
  }

All factories return `(signer, nil)` on success or `(nil, err)` on
malformed input. `from_env` is the one exception: unset / empty env
returns plain `nil` with no error so option-table composition stays
clean.
]]

local local_signer = require('pay_kit.signer.local')
local demo_signer = require('pay_kit.signer.demo')

local M = {}

-- --- helpers ---------------------------------------------------------

local function bytes_table_to_string(t)
  if type(t) ~= 'table' then
    return nil, 'pay_kit: secret must be a table of 64 byte integers'
  end
  if #t ~= 64 then
    return nil, 'pay_kit: secret must be a 64-element table'
  end
  local chars = {}
  for i = 1, 64 do
    local b = t[i]
    if type(b) ~= 'number' or b < 0 or b > 255 or b ~= math.floor(b) then
      return nil, 'pay_kit: secret bytes must be 0..255 integers (index ' .. i .. ')'
    end
    chars[i] = string.char(b)
  end
  return table.concat(chars)
end

local function hex_to_bytes(s)
  if type(s) ~= 'string' or #s ~= 128 then
    return nil, 'pay_kit: hex secret must be a 128-character string'
  end
  if not s:match('^[0-9a-fA-F]+$') then
    return nil, 'pay_kit: hex secret has non-hex characters'
  end
  local out = {}
  for i = 1, 128, 2 do
    out[#out + 1] = string.char(tonumber(s:sub(i, i + 1), 16))
  end
  return table.concat(out)
end

-- --- factories -------------------------------------------------------

-- Hard-coded demo keypair (singleton). Same identity across the
-- Lua and Ruby SDKs.
function M.demo()
  return demo_signer.instance()
end

-- Build a Local signer from a 64-element table of byte integers
-- (Solana CLI keypair JSON's parsed form).
function M.bytes(table_of_ints)
  local str, err = bytes_table_to_string(table_of_ints)
  if err then return nil, err end
  return local_signer.new(str)
end

-- Build a Local signer from a Solana-CLI JSON-array string
-- (`"[1, 2, ..., 64]"`).
function M.json(json_str)
  if type(json_str) ~= 'string' then
    return nil, 'pay_kit: signer.json: expected a string'
  end
  local trimmed = json_str:match('^%s*(.-)%s*$')
  if trimmed == '' then
    return nil, 'pay_kit: signer.json: empty input'
  end
  local cjson_safe = require('cjson.safe')
  local parsed, decode_err = cjson_safe.decode(trimmed)
  if not parsed then
    return nil, 'pay_kit: signer.json: invalid JSON: ' .. tostring(decode_err)
  end
  return M.bytes(parsed)
end

-- Build a Local signer from a base58 representation of the 64-byte
-- secret (the Phantom / Solflare export shape).
function M.base58(s)
  if type(s) ~= 'string' or #s == 0 then
    return nil, 'pay_kit: signer.base58: expected a non-empty string'
  end
  local base58 = require('pay_kit.solana.base58')
  local ok, bytes_or_err = pcall(base58.decode, s)
  if not ok then
    return nil, 'pay_kit: signer.base58: invalid base58: ' .. tostring(bytes_or_err)
  end
  if type(bytes_or_err) ~= 'string' or #bytes_or_err ~= 64 then
    return nil, 'pay_kit: signer.base58: decoded length must be 64 bytes'
  end
  return local_signer.new(bytes_or_err)
end

-- Build a Local signer from a 128-character hex string.
function M.hex(s)
  local bytes, err = hex_to_bytes(s)
  if err then return nil, err end
  return local_signer.new(bytes)
end

-- Read a Solana CLI keypair file (64-byte JSON array on disk).
function M.file(path)
  if type(path) ~= 'string' or path == '' then
    return nil, 'pay_kit: signer.file: expected a non-empty path'
  end
  local fh, open_err = io.open(path, 'rb')
  if not fh then
    return nil, 'pay_kit: signer.file: ' .. tostring(open_err)
  end
  local contents = fh:read('*a')
  fh:close()
  return M.json(contents)
end

-- Read an env var and auto-detect the encoding (JSON array, hex,
-- base58). Unset or empty env returns plain `nil` so the operator
-- option table's nil-as-no-opinion contract composes cleanly. Set
-- but malformed env returns `(nil, err)` because that is a real bug.
function M.from_env(name)
  if type(name) ~= 'string' or name == '' then
    return nil, 'pay_kit: signer.from_env: expected an env-var name'
  end
  local raw = os.getenv(name)
  if raw == nil or raw == '' then return nil end
  local trimmed = raw:match('^%s*(.-)%s*$')
  if trimmed == '' then return nil end
  if trimmed:sub(1, 1) == '[' then return M.json(trimmed) end
  if #trimmed == 128 and trimmed:match('^[0-9a-fA-F]+$') then
    return M.hex(trimmed)
  end
  return M.base58(trimmed)
end

-- Generate a fresh ephemeral keypair. Test-only; returns
-- `(nil, err)` when no keypair-generation backend is available
-- (the openssl-only environments cannot synthesise a Solana
-- 64-byte secret without seed derivation - production callers
-- load from files or env vars instead).
function M.generate()
  local ed25519 = require('pay_kit.util.ed25519')
  local secret, err = ed25519.generate()
  if not secret then return nil, err end
  return local_signer.new(secret)
end

return M
