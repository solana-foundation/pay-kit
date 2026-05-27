--[[
Cosign a base64-encoded Solana transaction with a 64-byte secret.

The legacy `pay_kit.solana.local_signer:cosign_base64` does the same
thing but routes the actual Ed25519 sign through luasodium. This
helper goes through `pay_kit.util.ed25519` so the backend
choice (openssl preferred, luasodium fallback) is consistent across
the umbrella.

The cosign path: parse the envelope, find the account index that
matches the cosigner's public key, sign the message bytes, overwrite
that signature slot, re-serialize to base64.
]]

local base58 = require('pay_kit.solana.base58')
local tx_mod = require('pay_kit.solana.transaction')
local ed25519 = require('pay_kit.util.ed25519')

local M = {}

-- Cosign a base64-encoded transaction with a 64-byte Solana secret.
-- Returns the cosigned transaction as a base64 string, ready to feed
-- into Solana RPC `sendTransaction` with `encoding: "base64"`.
-- Raises if the signer's pubkey is not in the account-keys slot, or
-- if the slot is outside the required-signers range.
function M.cosign_base64(transaction_b64, secret_64)
  if type(secret_64) ~= 'string' or #secret_64 ~= 64 then
    error('pay_kit.tx_cosign: secret must be a 64-byte binary string')
  end
  local public_32 = secret_64:sub(33, 64)
  local pubkey_b58 = base58.encode(public_32)

  local tx = tx_mod.from_base64(transaction_b64)
  local index = tx_mod.index_of_account(tx, pubkey_b58)
  if index == nil then
    error('pay_kit.tx_cosign: signer public key not present in transaction account keys')
  end
  local required = tx.message.header.required_signatures
  if index > required then
    error('pay_kit.tx_cosign: signer is not a required signer in this transaction')
  end

  local signature, err = ed25519.sign(secret_64, tx.message.raw)
  if not signature then error(err) end
  tx_mod.replace_signature(tx, index, signature)
  return tx_mod.to_base64(tx)
end

return M
