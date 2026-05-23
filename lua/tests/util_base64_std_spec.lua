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

helper.test('base64_std round-trips a 256-byte buffer', function()
  local bytes = {}
  for i = 0, 255 do
    bytes[#bytes + 1] = string.char(i)
  end
  local raw = table.concat(bytes)
  helper.assert_equal(base64_std.decode(base64_std.encode(raw)), raw)
end)
