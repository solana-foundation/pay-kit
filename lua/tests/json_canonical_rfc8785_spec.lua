-- RFC 8785 (JSON Canonicalization Scheme) test cases for the Lua SDK.
-- Isolated from core_spec.lua per PR #102 review (inline comment 3298060956)
-- so RFC 8785 (canonical JSON) and RFC 3339 (expires parser) live in
-- dedicated files. Battle-tested vector imports are tracked separately
-- (see follow-up issue referenced on the same PR thread).
local t = require('tests.test_helper')

t.test('canonical JSON sorts keys by UTF-16 code units (RFC 8785 sec 3.2.3)', function()
  local json = require('mpp.util.json')
  -- 'é' (U+00E9) > 'f' (U+0066) in UTF-16 code-unit order, so 'f' sorts first.
  local encoded = json.encode({ ['é'] = 1, f = 2 })
  t.assert_equal(encoded, '{"f":2,"\xC3\xA9":1}')
end)

t.test('canonical JSON serializes numbers per ES6 ToString', function()
  local json = require('mpp.util.json')
  t.assert_equal(json.encode(1e21), '1e+21')
  t.assert_equal(json.encode(0.1), '0.1')
  t.assert_equal(json.encode(-0.0), '0')
  t.assert_equal(json.encode(42), '42')
end)

t.test('canonical JSON rejects lone surrogates', function()
  local json = require('mpp.util.json')
  local lone = string.char(0xED, 0xA0, 0xB4)
  local ok = pcall(json.encode, { k = lone })
  t.assert_true(not ok)
end)

t.test('canonical JSON UTF-8 codepoint boundary', function()
  local json = require('mpp.util.json')
  -- U+10FFFF: max valid Unicode codepoint, F4 8F BF BF (accepted).
  local max_cp = string.char(0xF4, 0x8F, 0xBF, 0xBF)
  local ok = pcall(json.encode, { k = max_cp })
  t.assert_true(ok)
  -- U+110000: out-of-range, F4 90 80 80 (rejected).
  local out_of_range = string.char(0xF4, 0x90, 0x80, 0x80)
  local ok2 = pcall(json.encode, { k = out_of_range })
  t.assert_true(not ok2)
  -- F5+ leading byte rejected.
  local bad_lead = string.char(0xF5, 0x80, 0x80, 0x80)
  local ok3 = pcall(json.encode, { k = bad_lead })
  t.assert_true(not ok3)
end)

t.test('canonical JSON UTF-8 surrogate pair emoji round-trips', function()
  local json = require('mpp.util.json')
  -- U+1F600 grinning face, encoded as F0 9F 98 80 in UTF-8.
  local emoji = string.char(0xF0, 0x9F, 0x98, 0x80)
  local encoded = json.encode({ k = emoji })
  t.assert_equal(encoded, '{"k":"' .. emoji .. '"}')
end)

t.test('canonical JSON UTF-8 overlong sequences rejected', function()
  local json = require('mpp.util.json')
  -- Overlong 3-byte encoding of U+007F: E0 81 BF (rejected).
  local overlong3 = string.char(0xE0, 0x81, 0xBF)
  local ok = pcall(json.encode, { k = overlong3 })
  t.assert_true(not ok)
  -- Overlong 4-byte encoding of U+FFFF: F0 8F BF BF (rejected).
  local overlong4 = string.char(0xF0, 0x8F, 0xBF, 0xBF)
  local ok2 = pcall(json.encode, { k = overlong4 })
  t.assert_true(not ok2)
end)

t.test('canonical JSON ES6 ToString boundary cases', function()
  local json = require('mpp.util.json')
  t.assert_equal(json.encode(1e-6), '0.000001')
  t.assert_equal(json.encode(1e-7), '1e-7')
  t.assert_equal(json.encode(1e20), '100000000000000000000')
  t.assert_equal(json.encode(0.1 + 0.2), '0.30000000000000004')
end)

t.test('canonical JSON shortest round-trip needs 16 significant digits', function()
  -- Codex P2 on PR #102. Previously %.15g-then-%.17g returned "333333333.33333331"
  -- because %.15g does not round-trip; the correct ES6 ToString is "333333333.3333333"
  -- which requires exactly 16 significant digits.
  local json = require('mpp.util.json')
  t.assert_equal(json.encode(333333333.33333329), '333333333.3333333')
end)
