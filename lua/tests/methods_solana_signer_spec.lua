local helper = require('tests.test_helper')
local signer = require('mpp.methods.solana.signer')
local transaction = require('mpp.methods.solana.transaction')
local base58 = require('mpp.util.base58')

local sodium = require('luasodium')

-- Build a fresh keypair fixture once per spec so we do not rely on an
-- externally-generated test keypair.
local function fresh_keypair()
  local seed = string.rep('\7', 32)
  local pk, sk = sodium.crypto_sign_ed25519_seed_keypair(seed)
  return pk, sk
end

helper.test('signer.from_bytes exposes the matching public key as base58', function()
  local pk, sk = fresh_keypair()
  local s = signer.from_bytes(sk)
  helper.assert_equal(s.public_key, base58.encode(pk))
end)

helper.test('signer.from_bytes rejects a malformed secret key', function()
  helper.assert_error(function() signer.from_bytes('short') end, 'secret key must be exactly 64 bytes')
end)

helper.test('Signer:sign produces a libsodium-verifiable detached signature', function()
  local pk, sk = fresh_keypair()
  local s = signer.from_bytes(sk)
  local message = 'solana-mpp-cosign-test'
  local signature = s:sign(message)
  helper.assert_equal(#signature, 64)
  helper.assert_true(sodium.crypto_sign_ed25519_verify_detached(signature, message, pk))
end)

helper.test('Signer:sign_transaction patches the signature slot for the fee payer', function()
  local pk, sk = fresh_keypair()
  local s = signer.from_bytes(sk)
  -- Build a minimal legacy transaction whose account_keys[0] is the signer's
  -- public key, with required_signatures = 1. A placeholder all-zero
  -- signature occupies slot 1 and should be replaced after sign_transaction.
  local placeholder = string.rep('\0', 64)
  local blockhash = string.rep('\xc3', 32)
  local message = table.concat({
    string.char(1, 0, 0),
    transaction.compact_u16(1),
    pk,
    blockhash,
    transaction.compact_u16(0),
  })
  local raw = table.concat({
    transaction.compact_u16(1),
    placeholder,
    message,
  })
  local tx = transaction.from_bytes(raw)
  s:sign_transaction(tx)
  helper.assert_true(tx.signatures[1] ~= placeholder, 'signature slot must be overwritten')
  helper.assert_true(sodium.crypto_sign_ed25519_verify_detached(tx.signatures[1], tx.message.raw, pk))
end)

helper.test('Signer:sign_transaction rejects a transaction without the signer slot', function()
  local _pk, sk = fresh_keypair()
  local s = signer.from_bytes(sk)
  local random_key = string.rep('\xaa', 32)
  local placeholder = string.rep('\0', 64)
  local blockhash = string.rep('\xc3', 32)
  local message = table.concat({
    string.char(1, 0, 0),
    transaction.compact_u16(1),
    random_key,
    blockhash,
    transaction.compact_u16(0),
  })
  local raw = table.concat({
    transaction.compact_u16(1),
    placeholder,
    message,
  })
  local tx = transaction.from_bytes(raw)
  helper.assert_error(function() s:sign_transaction(tx) end, 'not present')
end)

helper.test('signer.from_json_array parses the Solana keypair-file format', function()
  local _pk, sk = fresh_keypair()
  local pieces = {}
  for i = 1, #sk do pieces[#pieces + 1] = tostring(sk:byte(i)) end
  local json_repr = '[' .. table.concat(pieces, ',') .. ']'
  local s = signer.from_json_array(json_repr)
  helper.assert_equal(#s.secret_key, 64)
end)
