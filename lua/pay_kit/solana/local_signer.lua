--[[
Ed25519 signer backed by luasodium.

The Lua MPP server runs in cosign mode when a fee-payer keypair is
configured: the client sends a partially-signed transaction, the
server detects its slot in `signatures`, signs the message bytes, and
writes the 64-byte signature back into that slot before broadcast.

Solana's canonical secret-key format is a 64-byte concatenation of
the 32-byte Ed25519 seed and the 32-byte public key. This matches
libsodium's `crypto_sign_ed25519_SECRETKEYBYTES` layout, so the same
bytes that come out of the Solana CLI / web3.js `Keypair` work here
without re-derivation.
]]

local base58 = require('pay_kit.solana.base58')
local transaction = require('pay_kit.solana.transaction')
local json = require('pay_kit.util.json')

local M = {}

-- Lazy-load luasodium so the module can be required from environments that
-- only need the parser side of the stack without paying the libsodium load.
local sodium
local function get_sodium()
  if sodium ~= nil then
    return sodium
  end
  local ok, lib = pcall(require, 'luasodium')
  if not ok then
    error('Ed25519 signer requires luasodium: ' .. tostring(lib))
  end
  sodium = lib
  return lib
end

local Signer = {}
Signer.__index = Signer

--- Construct a signer from raw secret-key bytes (64 bytes, Solana format).
function M.from_bytes(secret_key_bytes)
  if type(secret_key_bytes) ~= 'string' or #secret_key_bytes ~= 64 then
    error('secret key must be exactly 64 bytes')
  end
  local public_key_bytes = secret_key_bytes:sub(33, 64)
  return setmetatable({
    secret_key = secret_key_bytes,
    public_key_bytes = public_key_bytes,
    public_key = base58.encode(public_key_bytes),
  }, Signer)
end

--- Construct a signer from a JSON byte-array string (the canonical Solana
--- keypair-file format and the harness env-var contract).
function M.from_json_array(raw)
  local parsed = json.decode(raw)
  if type(parsed) ~= 'table' then
    error('secret key must be a JSON array')
  end
  local bytes = {}
  for i = 1, #parsed do
    local byte = parsed[i]
    if type(byte) ~= 'number' or byte < 0 or byte > 255 then
      error('secret key bytes must be 0..255 integers')
    end
    bytes[#bytes + 1] = string.char(byte)
  end
  return M.from_bytes(table.concat(bytes))
end

--- Sign raw bytes; returns the 64-byte detached signature.
function Signer:sign(message)
  return get_sodium().crypto_sign_ed25519_detached(message, self.secret_key)
end

--- Sign the message bytes of a parsed transaction and patch the matching
--- signer slot in place. Errors if the public key is not present in the
--- transaction's account keys or sits outside the required-signers range.
function Signer:sign_transaction(tx)
  local index = transaction.index_of_account(tx, self.public_key)
  if index == nil then
    error('signer public key not present in transaction account keys')
  end
  local required = tx.message.header.required_signatures
  if index > required then
    error('signer is not a required signer in this transaction')
  end
  local signature = self:sign(tx.message.raw)
  transaction.replace_signature(tx, index, signature)
  return signature
end

--- Convenience: decode a base64 transaction, sign it with this signer, and
--- return the cosigned base64 payload. Used by the charge handler's
--- `pull_transaction_signer` hook.
function Signer:cosign_base64(transaction_base64)
  local tx = transaction.from_base64(transaction_base64)
  self:sign_transaction(tx)
  return transaction.to_base64(tx)
end

M.Signer = Signer

return M
