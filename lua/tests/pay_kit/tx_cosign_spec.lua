--[[
Cosign helper. Synthesizes a tiny v0 transaction with the cosigner
slot at index 0 and exercises the sign+replace_signature+to_base64
round-trip. The cosigner public key is derived deterministically
from a 64-byte secret (sk[33..64] is the Ed25519 public key).
]]

local helper = require('tests.test_helper')
local base58 = require('pay_kit.solana.base58')
local base64 = require('pay_kit.util.base64_std')
local tx_mod = require('pay_kit.solana.transaction')
local tx_cosign = require('pay_kit.solana.tx_cosign')
local ed25519 = require('pay_kit.util.ed25519')

-- Synthesize a minimal v0 transaction. The cosigner's public key sits
-- at account_keys[0] (the single required signer); the message
-- contains exactly one no-op instruction against an arbitrary
-- program so we keep the wire shape valid.
local function synth_tx(cosigner_pubkey_32)
  local header = string.char(1, 0, 0)        -- 1 signer, 0 readonly signed, 0 readonly unsigned
  local account_count = tx_mod.compact_u16(2)
  local program_key = string.rep('\1', 32)
  local account_keys = cosigner_pubkey_32 .. program_key
  local recent_blockhash = string.rep('\0', 32)
  -- One instruction: program_index=1 (the dummy program), no accounts, empty data.
  local ix = string.char(1) .. tx_mod.compact_u16(0) .. tx_mod.compact_u16(0)
  local instructions_blob = tx_mod.compact_u16(1) .. ix
  local lookups = tx_mod.compact_u16(0)
  local message = '\x80' .. header .. account_count .. account_keys ..
                  recent_blockhash .. instructions_blob .. lookups
  local sig_count = tx_mod.compact_u16(1)
  local sigs = string.rep('\0', 64)
  return sig_count .. sigs .. message
end

helper.test('cosign_base64 rejects non-64-byte secret', function()
  local ok, err = pcall(tx_cosign.cosign_base64, base64.encode('x'), 'short')
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('64%-byte') ~= nil)
end)

helper.test('cosign_base64 raises when signer not in account keys', function()
  local secret = ed25519.generate()
  if not secret then return end
  local stranger_pub = string.rep('\7', 32)
  local raw = synth_tx(stranger_pub)
  local ok, err = pcall(tx_cosign.cosign_base64, base64.encode(raw), secret)
  helper.assert_true(not ok)
  helper.assert_true(tostring(err):find('not present in transaction', 1, true) ~= nil)
end)

helper.test('cosign_base64 round-trips: returned base64 parses and carries the signer pubkey', function()
  local secret = ed25519.generate()
  if not secret then return end
  local public_key = secret:sub(33, 64)
  local raw = synth_tx(public_key)
  local result = tx_cosign.cosign_base64(base64.encode(raw), secret)
  helper.assert_true(type(result) == 'string' and #result > 0)
  local decoded = base64.decode(result)
  helper.assert_true(decoded ~= nil, 'cosigned output must be valid base64')
  -- Parsing the cosigned envelope round-trips through tx_mod.
  local parsed = tx_mod.from_base64(result)
  helper.assert_equal(parsed.message.account_keys[1], base58.encode(public_key))
  -- The first signature slot must no longer be zero-bytes.
  helper.assert_true(parsed.signatures[1] ~= string.rep('\0', 64))
end)
