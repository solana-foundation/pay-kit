--[[
Additional signer factory coverage. The existing signer_spec covers
demo + bytes + json + file roundtrips; this spec hits the error
branches and the from_env auto-detect paths that earlier specs
skipped.
]]

local helper = require('tests.test_helper')
local signer = require('pay_kit.signer')

helper.test('signer.json rejects non-string input', function()
  local s, err = signer.json(42)
  helper.assert_true(s == nil)
  helper.assert_true(tostring(err):find('expected a string', 1, true) ~= nil)
end)

helper.test('signer.base58 rejects non-string input', function()
  local s, err = signer.base58(42)
  helper.assert_true(s == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('signer.base58 rejects empty string', function()
  local s, err = signer.base58('')
  helper.assert_true(s == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('signer.base58 rejects invalid base58 chars', function()
  -- '0' is not in the bitcoin base58 alphabet; pay_kit.solana.base58 raises.
  local s, err = signer.base58('0000000000000')
  helper.assert_true(s == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('signer.base58 rejects decoded-length != 64', function()
  -- Short base58 string that decodes to fewer than 64 bytes.
  local base58 = require('pay_kit.solana.base58')
  local short = base58.encode(string.rep('\1', 16))
  local s, err = signer.base58(short)
  helper.assert_true(s == nil)
  helper.assert_true(tostring(err):find('64 bytes', 1, true) ~= nil)
end)

helper.test('signer.file rejects non-string path', function()
  local s, err = signer.file(nil)
  helper.assert_true(s == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('signer.file rejects empty path', function()
  local s, err = signer.file('')
  helper.assert_true(s == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('signer.from_env rejects empty name', function()
  local s, err = signer.from_env('')
  helper.assert_true(s == nil)
  helper.assert_true(err ~= nil)
end)

helper.test('signer.from_env returns nil for unset env (no error)', function()
  local s, err = signer.from_env('PAY_KIT_TEST_UNSET_X9Y8Z7')
  helper.assert_true(s == nil)
  helper.assert_true(err == nil)
end)

helper.test('signer.from_env auto-detects JSON-array shape', function()
  -- Inject a JSON-array secret via os.getenv monkey patch.
  local saved = os.getenv
  local sk = {}
  for i = 1, 64 do sk[#sk + 1] = ((i * 7) % 256) end
  local json_array = '[' .. table.concat(sk, ',') .. ']'
  os.getenv = function(n) -- luacheck: ignore
    if n == 'PAY_KIT_TEST_JSON' then return json_array end
    return saved(n)
  end
  local s = signer.from_env('PAY_KIT_TEST_JSON')
  os.getenv = saved -- luacheck: ignore
  helper.assert_true(s ~= nil)
end)

helper.test('signer.from_env auto-detects hex shape (128 chars)', function()
  local saved = os.getenv
  local hex = string.rep('aa', 64)  -- 128-char hex
  os.getenv = function(n) -- luacheck: ignore
    if n == 'PAY_KIT_TEST_HEX' then return hex end
    return saved(n)
  end
  local s = signer.from_env('PAY_KIT_TEST_HEX')
  os.getenv = saved -- luacheck: ignore
  helper.assert_true(s ~= nil)
end)

helper.test('signer.from_env falls back to base58 detect', function()
  local base58 = require('pay_kit.solana.base58')
  local sk_bytes = {}
  for i = 1, 64 do sk_bytes[#sk_bytes + 1] = string.char((i * 13) % 256) end
  local b58 = base58.encode(table.concat(sk_bytes))
  local saved = os.getenv
  os.getenv = function(n) -- luacheck: ignore
    if n == 'PAY_KIT_TEST_B58' then return b58 end
    return saved(n)
  end
  local s = signer.from_env('PAY_KIT_TEST_B58')
  os.getenv = saved -- luacheck: ignore
  helper.assert_true(s ~= nil)
end)

helper.test('signer.from_env: whitespace-only env returns nil', function()
  local saved = os.getenv
  os.getenv = function(n) -- luacheck: ignore
    if n == 'PAY_KIT_TEST_WS' then return '   ' end
    return saved(n)
  end
  local s, err = signer.from_env('PAY_KIT_TEST_WS')
  os.getenv = saved -- luacheck: ignore
  helper.assert_true(s == nil)
  helper.assert_true(err == nil)
end)

helper.test('signer.bytes rejects bad byte-table entries', function()
  local sk = {}
  for i = 1, 64 do sk[#sk + 1] = 1 end
  sk[10] = -1  -- out of range
  local s, err = signer.bytes(sk)
  helper.assert_true(s == nil)
  helper.assert_true(tostring(err):find('0..255', 1, true) ~= nil)
end)
