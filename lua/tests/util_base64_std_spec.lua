local helper = require('tests.test_helper')
local base64_std = require('mpp.util.base64_std')

helper.test('base64_std encode handles the canonical RFC 4648 vectors', function()
  helper.assert_equal(base64_std.encode(''), '')
  helper.assert_equal(base64_std.encode('f'), 'Zg==')
  helper.assert_equal(base64_std.encode('fo'), 'Zm8=')
  helper.assert_equal(base64_std.encode('foo'), 'Zm9v')
  helper.assert_equal(base64_std.encode('foob'), 'Zm9vYg==')
  helper.assert_equal(base64_std.encode('fooba'), 'Zm9vYmE=')
  helper.assert_equal(base64_std.encode('foobar'), 'Zm9vYmFy')
end)

helper.test('base64_std decode handles the canonical RFC 4648 vectors', function()
  helper.assert_equal(base64_std.decode(''), '')
  helper.assert_equal(base64_std.decode('Zg=='), 'f')
  helper.assert_equal(base64_std.decode('Zm8='), 'fo')
  helper.assert_equal(base64_std.decode('Zm9v'), 'foo')
  helper.assert_equal(base64_std.decode('Zm9vYg=='), 'foob')
  helper.assert_equal(base64_std.decode('Zm9vYmE='), 'fooba')
  helper.assert_equal(base64_std.decode('Zm9vYmFy'), 'foobar')
end)

helper.test('base64_std preserves the + and / characters distinct from URL-safe variant', function()
  -- The bytes 0xfb 0xff produce '+/8=' under the standard alphabet but '-_8'
  -- under URL-safe; this test asserts the standard variant is in use.
  local encoded = base64_std.encode('\xfb\xff')
  helper.assert_equal(encoded:sub(1, 1), '+')
end)

-- Codex PR #103 P2: strict_decode parity with Ruby's Base64.strict_decode64.
helper.test('base64_std decode rejects internal padding (Zm=9)', function()
  helper.assert_error(function() base64_std.decode('Zm=9') end, 'invalid base64')
end)

helper.test('base64_std decode rejects non-multiple-of-4 length', function()
  helper.assert_error(function() base64_std.decode('Zm9') end, 'multiple of 4')
end)

helper.test('base64_std decode rejects non-alphabet characters', function()
  helper.assert_error(function() base64_std.decode('Zm9*') end, 'invalid base64 character')
end)

helper.test('base64_std decode rejects three trailing pads', function()
  helper.assert_error(function() base64_std.decode('Zg=====') end, 'multiple of 4')
end)

helper.test('base64_std decode rejects non-canonical trailing bits', function()
  -- 'Ah==' would decode to a single byte but the low 4 bits of 'h' (33)
  -- are not zero, so it is not a canonical Base64 encoding.
  helper.assert_error(function() base64_std.decode('Ah==') end, 'trailing bits')
end)

helper.test('base64_std decode rejects embedded whitespace', function()
  helper.assert_error(function() base64_std.decode('Zm9v Yg==') end, 'multiple of 4')
end)

helper.test('base64_std round-trips a 256-byte buffer', function()
  local bytes = {}
  for i = 0, 255 do
    bytes[#bytes + 1] = string.char(i)
  end
  local raw = table.concat(bytes)
  helper.assert_equal(base64_std.decode(base64_std.encode(raw)), raw)
end)
