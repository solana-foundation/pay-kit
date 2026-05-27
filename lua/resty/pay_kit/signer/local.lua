--[[
Local in-process Ed25519 signer.

Wraps the existing `mpp.methods.solana.signer` (luasodium-backed) so
PayKit avoids re-implementing the Ed25519 primitives that already live
in the MPP layer. The public duck-type contract — `:pubkey()`, `:sign()`,
`:fee_payer()`, `:demo()` — is what every PayKit code path consumes;
future remote signers under `resty.pay_kit.kms` will satisfy the same
contract with cosocket I/O on `:sign()`.

Per Decision #7 in the design notes, the crypto backend will migrate
from luasodium to `lua-resty-openssl` in a follow-up so Kong / APISIX
operators do not need libsodium installed system-wide. The interface
this module exposes does not change with that swap.
]]

local mpp_signer = require('mpp.methods.solana.signer')

local M = {}
local Signer = {}
Signer.__index = Signer

-- Build a Local signer from a 64-byte secret-key string (Solana's
-- canonical layout: 32-byte seed || 32-byte public key). Raises an
-- error for the wrong length so a bad key dies at construct-time,
-- not at first sign.
function M.new(secret_key_bytes)
  if type(secret_key_bytes) ~= 'string' or #secret_key_bytes ~= 64 then
    error('pay_kit.signer: secret must be a 64-byte binary string')
  end
  local inner = mpp_signer.from_bytes(secret_key_bytes)
  return setmetatable({
    _inner = inner,
    _secret_bytes = secret_key_bytes,
    _is_demo = false,
  }, Signer)
end

-- Base58 Solana public key (44-character string).
function Signer:pubkey()
  return self._inner.public_key
end

-- Sign raw message bytes; returns a 64-byte detached Ed25519 signature.
-- Mirrors the design's `(result, err)` contract by never raising on
-- normal control flow - the inner luasodium call is wrapped in pcall.
function Signer:sign(message)
  local ok, sig_or_err = pcall(function() return self._inner:sign(message) end)
  if not ok then
    return nil, 'pay_kit: signer failed to sign: ' .. tostring(sig_or_err)
  end
  return sig_or_err
end

-- Whether this signer should pay Solana network fees on settlement
-- transactions. True for local signers; remote / KMS signers may flip
-- this off when fees come from elsewhere.
function Signer:fee_payer()
  return true
end

-- Subclasses (`resty.pay_kit.signer.demo`) override this to return
-- true. `pay_kit.configure` reads it to enforce the mainnet refusal
-- rule for the published demo keypair.
function Signer:demo()
  return self._is_demo
end

-- Internal: hand back the raw secret bytes. Used by the MPP / x402
-- adapters that still want a `secret_key` for the underlying mpp
-- protocol layer during the transition. Not part of the public API.
function Signer:_secret_key_bytes()
  return self._secret_bytes
end

-- Internal: marker for the demo singleton so the demo factory can
-- toggle `:demo()` without exposing a public setter.
function Signer:_mark_demo()
  self._is_demo = true
  return self
end

-- Internal: hand back the underlying mpp-layer signer (the luasodium
-- wrapper). Used by adapters that need `sign_transaction` for the MPP
-- charge handler's cosign path.
function Signer:_inner_mpp_signer()
  return self._inner
end

return M
