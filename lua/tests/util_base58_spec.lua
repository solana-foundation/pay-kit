local helper = require('tests.test_helper')
local base58 = require('mpp.util.base58')

local function from_hex(hex)
  local out = {}
  for i = 1, #hex, 2 do
    out[#out + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
  end
  return table.concat(out)
end

helper.test('base58 encode matches the Ruby reference for the system program id', function()
  -- 32 zero bytes encode to the canonical Solana System Program id.
  helper.assert_equal(base58.encode(string.rep('\0', 32)), '11111111111111111111111111111111')
end)

helper.test('base58 round-trips a known Solana public key', function()
  local key = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
  local decoded = base58.decode(key)
  helper.assert_equal(#decoded, 32)
  helper.assert_equal(base58.encode(decoded), key)
end)

helper.test('base58 round-trips an arbitrary byte string', function()
  local sample = from_hex('00010203deadbeefcafef00d11223344556677889900aabbccddeeff0102030405')
  helper.assert_equal(base58.encode(base58.decode(base58.encode(sample))), base58.encode(sample))
end)

helper.test('base58 preserves leading zero bytes as leading ones', function()
  -- Leading-zero invariant: each leading 0x00 byte maps to one leading '1'.
  local input = '\0\0\1\2'
  local encoded = base58.encode(input)
  helper.assert_equal(encoded:sub(1, 2), '11')
  helper.assert_equal(base58.decode(encoded), input)
end)

helper.test('base58 decode rejects an out-of-alphabet character', function()
  helper.assert_error(function()
    base58.decode('0OIl')
  end, 'invalid base58')
end)

helper.test('base58 encodes the empty string to empty', function()
  helper.assert_equal(base58.encode(''), '')
  helper.assert_equal(base58.decode(''), '')
end)

helper.test('base58 round-trips a 64-byte signature payload', function()
  local payload = from_hex(string.rep('5a', 64))
  local encoded = base58.encode(payload)
  -- Ed25519 signatures are 87 or 88 characters under base58.
  helper.assert_true(#encoded >= 87 and #encoded <= 88, 'expected 87-88 char signature length, got ' .. tostring(#encoded))
  helper.assert_equal(base58.decode(encoded), payload)
end)
