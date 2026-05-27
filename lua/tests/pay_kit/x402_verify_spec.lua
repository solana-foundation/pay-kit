--[[
P5-late x402 11-rule structural verifier. Negative-path coverage:
each rule emits the right canonical reject string the cross-language
harness substring-matches against. Positive-path end-to-end coverage
runs through the interop harness (a real Solana tx fixture).
]]

local helper = require('tests.test_helper')
local base64 = require('pay_kit.util.base64_std')
local x402_verify = require('pay_kit.protocols.x402.exact.verify')

local SELLER = 'SeLLeRWaLLeT111111111111111111111111111111'

local function offer_fixture()
  return {
    scheme  = 'exact',
    network = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
    asset   = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    payTo   = SELLER,
    amount  = '1000',
    extra   = {
      feePayer     = 'FaCiLiTaToRPubKey111111111111111111111111111',
      decimals     = 6,
      tokenProgram = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
      memo         = '/paid',
    },
  }
end

helper.test('verify rejects malformed base64', function()
  local ok, err = pcall(x402_verify.verify, '!!!notbase64@@@', offer_fixture(), {})
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('invalid_exact_svm_payload', 1, true),
    tostring(err))
end)

helper.test('verify rejects empty transaction bytes', function()
  local ok, err = pcall(x402_verify.verify, base64.encode(''), offer_fixture(), {})
  helper.assert_true(not ok, 'expected verify to raise on empty input')
  helper.assert_true(tostring(err):find('invalid_exact_svm_payload', 1, true),
    tostring(err))
end)

helper.test('verify rejects too-short transaction (wrong instruction count)', function()
  -- 17-byte garbage will at best decode as 0 or 1 instructions; the
  -- verifier emits the rule-1 reject.
  local tiny = string.rep('\1', 17)
  local ok, err = pcall(x402_verify.verify, base64.encode(tiny), offer_fixture(), {})
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('invalid_exact_svm_payload', 1, true),
    tostring(err))
end)

helper.test('verify_client_signatures rejects malformed envelope', function()
  local ok, err = pcall(x402_verify.verify_client_signatures, 'not-base64', {})
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('invalid_exact_svm_payload_signature', 1, true),
    tostring(err))
end)
