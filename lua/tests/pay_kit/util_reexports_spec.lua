--[[
Smoke that the public-surface re-export shims in resty/pay_kit/util/
and resty/pay_kit/solana/ load and return the underlying module.
Covers the single return statement luacov reports as uncovered when
no test requires the shim.
]]

local helper = require('tests.test_helper')

helper.test('pay_kit.solana.base58 re-exports the legacy pay_kit.solana.base58', function()
  local b58 = require('pay_kit.solana.base58')
  helper.assert_equal(type(b58.encode), 'function')
  helper.assert_equal(type(b58.decode), 'function')
end)

helper.test('pay_kit.util.base64url re-exports the legacy module', function()
  local b64u = require('pay_kit.util.base64url')
  helper.assert_equal(type(b64u.encode), 'function')
  helper.assert_equal(type(b64u.decode), 'function')
end)

helper.test('pay_kit.util.json re-exports the canonical JSON module', function()
  local j = require('pay_kit.util.json')
  helper.assert_true(type(j.encode) == 'function' or type(j.decode) == 'function'
    or type(j) == 'table')
end)

helper.test('pay_kit.util.crypto exposes ed25519 + hmac surface', function()
  local crypto = require('pay_kit.util.crypto')
  helper.assert_true(type(crypto.ed25519) == 'table')
  helper.assert_equal(type(crypto.ed25519.sign), 'function')
  helper.assert_equal(type(crypto.hmac_sha256), 'function')
  helper.assert_equal(type(crypto.constant_time_equal), 'function')
end)

helper.test('pay_kit.solana.rpc re-exports the cosocket RPC client', function()
  local rpc = require('pay_kit.solana.rpc')
  helper.assert_equal(type(rpc.new), 'function')
end)
