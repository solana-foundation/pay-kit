--[[
P1 signer factory family + Demo singleton + Local wrapper.

Mirrors the Ruby gem's `test/pay_kit/signer_test.rb` so the two SDKs
stay locked to the same surface contract (`pubkey`, `sign`,
`fee_payer`, `demo` duck-type), the same factory set
(`bytes/json/base58/hex/file/from_env/generate`), and the same
nil-as-no-opinion behaviour on `from_env`.
]]

local helper = require('tests.test_helper')
local signer = require('pay_kit.signer')
local demo_signer = require('pay_kit.signer.demo')

-- 64-byte non-demo test secret. Distinct from the published demo
-- keypair so factory paths cover the non-demo branch too.
local RAW_BYTES = {}
for i = 1, 64 do RAW_BYTES[i] = i end

local function chars_from_bytes(t)
  local out = {}
  for i = 1, #t do out[i] = string.char(t[i]) end
  return table.concat(out)
end
local RAW_SECRET_STRING = chars_from_bytes(RAW_BYTES)

-- Derive the public key by going through the same luasodium path
-- the inner signer uses, so we can assert pubkey shape without
-- duplicating Ed25519 derivation in the test.
local function pubkey_of(secret_string)
  local mpp_signer = require('pay_kit.solana.local_signer')
  return mpp_signer.from_bytes(secret_string).public_key
end
local RAW_PUBKEY = pubkey_of(RAW_SECRET_STRING)

local function bytes_table_copy(t)
  local out = {}
  for i = 1, #t do out[i] = t[i] end
  return out
end

-- --- duck-type contract --------------------------------------------

helper.test('signer.bytes returns a Local satisfying the duck type', function()
  local sgn, err = signer.bytes(bytes_table_copy(RAW_BYTES))
  helper.assert_true(sgn ~= nil and err == nil, 'expected (signer, nil)')
  helper.assert_equal(type(sgn.pubkey(sgn)), 'string')
  helper.assert_equal(sgn:pubkey(), RAW_PUBKEY)
  helper.assert_equal(sgn:fee_payer(), true)
  helper.assert_equal(sgn:demo(), false)
  local sig = sgn:sign('hello')
  helper.assert_equal(type(sig), 'string')
  helper.assert_equal(#sig, 64)
end)

-- --- demo -----------------------------------------------------------

helper.test('signer.demo returns the package demo keypair with demo()=true', function()
  demo_signer.reset_for_tests()
  local d = signer.demo()
  helper.assert_equal(d:pubkey(), demo_signer.PUBKEY)
  helper.assert_equal(d:demo(), true)
  helper.assert_equal(d:fee_payer(), true)
end)

helper.test('signer.demo is cached (same instance across calls)', function()
  demo_signer.reset_for_tests()
  local a = signer.demo()
  local b = signer.demo()
  helper.assert_true(a == b, 'demo singleton should be reused')
end)

helper.test('signer.bytes with the demo secret does not flag demo=true', function()
  demo_signer.reset_for_tests()
  local d_str = chars_from_bytes(demo_signer.SECRET_BYTES)
  -- Build a fresh local via the bytes factory; it must NOT report
  -- demo=true because only the demo factory marks the instance.
  local copied = {}
  for i = 1, #demo_signer.SECRET_BYTES do copied[i] = demo_signer.SECRET_BYTES[i] end
  local sgn, err = signer.bytes(copied)
  helper.assert_true(sgn and not err)
  helper.assert_equal(sgn:demo(), false)
  -- But the pubkey still matches the demo identity.
  helper.assert_equal(sgn:pubkey(), demo_signer.PUBKEY)
  -- And signs the same bytes.
  local sig_a = sgn:sign(d_str)
  helper.assert_equal(#sig_a, 64)
end)

-- --- bytes / json / base58 / hex validation ------------------------

helper.test('signer.bytes rejects wrong length', function()
  local _, err = signer.bytes({1, 2, 3})
  helper.assert_true(err and err:find('64-element', 1, true), err)
end)

helper.test('signer.bytes rejects non-table input', function()
  local _, err = signer.bytes('not a table')
  helper.assert_true(err and err:find('table'), err)
end)

helper.test('signer.bytes rejects out-of-range bytes', function()
  local bytes = bytes_table_copy(RAW_BYTES)
  bytes[1] = 300
  local _, err = signer.bytes(bytes)
  helper.assert_true(err and err:find('0..255'), err)
end)

helper.test('signer.json parses a Solana CLI JSON array', function()
  local cjson = require('cjson.safe')
  local sgn, err = signer.json(cjson.encode(RAW_BYTES))
  helper.assert_true(sgn and not err, err)
  helper.assert_equal(sgn:pubkey(), RAW_PUBKEY)
end)

helper.test('signer.json rejects malformed input', function()
  local _, err = signer.json('not json at all')
  helper.assert_true(err and err:find('invalid JSON'), err)
end)

helper.test('signer.json rejects empty input', function()
  local _, err = signer.json('   ')
  helper.assert_true(err and err:find('empty'), err)
end)

helper.test('signer.hex accepts a 128-char string', function()
  local hex_chars = {}
  for i = 1, 64 do
    hex_chars[#hex_chars + 1] = string.format('%02x', RAW_BYTES[i])
  end
  local sgn, err = signer.hex(table.concat(hex_chars))
  helper.assert_true(sgn and not err, err)
  helper.assert_equal(sgn:pubkey(), RAW_PUBKEY)
end)

helper.test('signer.hex rejects wrong length', function()
  local _, err = signer.hex('abc')
  helper.assert_true(err and err:find('128'), err)
end)

helper.test('signer.hex rejects non-hex characters', function()
  local _, err = signer.hex(string.rep('zz', 64))
  helper.assert_true(err and err:find('non%-hex'), err)
end)

helper.test('signer.base58 accepts the base58 encoding of the 64-byte secret', function()
  local base58 = require('pay_kit.solana.base58')
  local sgn, err = signer.base58(base58.encode(RAW_SECRET_STRING))
  helper.assert_true(sgn and not err, err)
  helper.assert_equal(sgn:pubkey(), RAW_PUBKEY)
end)

-- --- file -----------------------------------------------------------

helper.test('signer.file reads a JSON-array keypair file', function()
  local cjson = require('cjson.safe')
  local tmp = os.tmpname()
  local fh = io.open(tmp, 'w')
  fh:write(cjson.encode(RAW_BYTES))
  fh:close()
  local sgn, err = signer.file(tmp)
  os.remove(tmp)
  helper.assert_true(sgn and not err, err)
  helper.assert_equal(sgn:pubkey(), RAW_PUBKEY)
end)

helper.test('signer.file errors on missing path', function()
  local _, err = signer.file('/no/such/path/keypair.json')
  helper.assert_true(err and err:find('signer.file'), err)
end)

-- --- from_env -------------------------------------------------------
--
-- These tests use a UNIQUE env-var name per test to avoid leaking
-- state between cases under busted-vari runners.

helper.test('signer.from_env returns nil for unset env (no error)', function()
  local sgn, err = signer.from_env('PAY_KIT_TEST_SIGNER_DEFINITELY_UNSET')
  helper.assert_true(sgn == nil and err == nil, 'expected (nil, nil) for unset env')
end)

helper.test('signer.from_env returns nil for empty env', function()
  -- Lua's os.setenv is non-standard; do it via a subprocess if needed.
  -- Skip when setenv is unavailable. The hex path covers the same logic.
  local ok, posix = pcall(require, 'posix.stdlib')
  if not ok then return end
  posix.setenv('PAY_KIT_TEST_SIGNER_EMPTY', '')
  local sgn, err = signer.from_env('PAY_KIT_TEST_SIGNER_EMPTY')
  helper.assert_true(sgn == nil and err == nil, 'expected (nil, nil) for empty env')
  -- Empty-string env vars are technically set; clean up via unsetenv.
  pcall(function() posix.unsetenv('PAY_KIT_TEST_SIGNER_EMPTY') end)
end)

helper.test('signer.from_env decodes a JSON-array env var', function()
  local ok, posix = pcall(require, 'posix.stdlib')
  if not ok then return end
  local cjson = require('cjson.safe')
  posix.setenv('PAY_KIT_TEST_SIGNER_JSON', cjson.encode(RAW_BYTES))
  local sgn, err = signer.from_env('PAY_KIT_TEST_SIGNER_JSON')
  pcall(function() posix.unsetenv('PAY_KIT_TEST_SIGNER_JSON') end)
  helper.assert_true(sgn and not err, err)
  helper.assert_equal(sgn:pubkey(), RAW_PUBKEY)
end)

-- --- generate -------------------------------------------------------

helper.test('signer.generate returns a fresh keypair each call', function()
  local a, err_a = signer.generate()
  if err_a then return end -- luasodium absent; skip silently
  local b = signer.generate()
  helper.assert_true(a:pubkey() ~= b:pubkey(), 'consecutive generate() should return distinct pubkeys')
  helper.assert_equal(#a:sign('x'), 64)
end)

-- --- error-branch + from_env auto-detect coverage (merged from signer_more_spec) ---
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
