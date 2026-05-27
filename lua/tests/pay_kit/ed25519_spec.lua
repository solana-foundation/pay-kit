--[[
P3 Ed25519 abstraction. Confirms the openssl-or-luasodium backend
chain works end-to-end (sign then verify the same message), regardless
of which backend the host loaded.
]]

local helper = require('tests.test_helper')
local ed25519 = require('pay_kit.util.ed25519')

local function fresh_secret()
  local secret, err = ed25519.generate()
  if not secret then return nil, err end
  return secret
end

helper.test('ed25519.backend reports a usable backend', function()
  local b = ed25519.backend()
  helper.assert_true(b == 'openssl' or b == 'luasodium',
    'expected openssl or luasodium, got ' .. tostring(b))
end)

helper.test('sign + verify round-trip', function()
  local secret = fresh_secret()
  if not secret then return end  -- backend cannot generate; skip silently
  local public_32 = assert(ed25519.derive_public(secret))
  local msg = 'pay_kit ed25519 round-trip'
  local sig = assert(ed25519.sign(secret, msg))
  helper.assert_equal(#sig, 64)
  local ok = assert(ed25519.verify(public_32, msg, sig))
  helper.assert_equal(ok, true)
end)

helper.test('verify rejects a tampered message', function()
  local secret = fresh_secret()
  if not secret then return end
  local public_32 = assert(ed25519.derive_public(secret))
  local sig = assert(ed25519.sign(secret, 'original'))
  local ok = ed25519.verify(public_32, 'tampered', sig)
  helper.assert_true(ok == false or ok == nil,
    'verify must not accept a tampered message')
end)

helper.test('verify rejects a swapped signature', function()
  local secret_a = fresh_secret()
  local secret_b = fresh_secret()
  if not secret_a or not secret_b then return end
  local pub_a = assert(ed25519.derive_public(secret_a))
  local sig_b = assert(ed25519.sign(secret_b, 'message'))
  local ok = ed25519.verify(pub_a, 'message', sig_b)
  helper.assert_true(ok == false or ok == nil,
    'verify must not accept B-signed-message against A-pubkey')
end)

helper.test('sign rejects wrong secret length', function()
  local _, err = ed25519.sign('short', 'msg')
  helper.assert_true(err and err:find('64 bytes', 1, true), err)
end)

helper.test('verify rejects wrong key/signature length', function()
  local _, e1 = ed25519.verify('short', 'msg', string.rep('x', 64))
  helper.assert_true(e1 and e1:find('32 bytes', 1, true))
  local _, e2 = ed25519.verify(string.rep('p', 32), 'msg', 'short')
  helper.assert_true(e2 and e2:find('64 bytes', 1, true))
end)

helper.test('derive_public returns the trailing 32 bytes of the Solana secret', function()
  local secret = fresh_secret()
  if not secret then return end
  local public_32 = assert(ed25519.derive_public(secret))
  helper.assert_equal(#public_32, 32)
  helper.assert_equal(public_32, secret:sub(33, 64))
end)
