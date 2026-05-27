--[[
Local in-process Ed25519 signer.

Two backends can power the signing primitive (see
`pay_kit.util.ed25519`): `lua-resty-openssl` when available
(Kong / APISIX / OpenResty production path) and `luasodium` as the
plain-LuaJIT fallback. The choice is transparent to callers - this
file only sees the `ed25519.sign / .derive_public` surface.

Public contract (the duck type every PayKit code path consumes):
- `:pubkey()`    base58 Solana public key (44-character string)
- `:sign(msg)`   64-byte detached Ed25519 signature
- `:fee_payer()` true for local signers
- `:demo()`      true only for the published demo singleton

Future remote signers under `pay_kit.kms` satisfy the same
contract with cosocket I/O on `:sign`. OpenResty cosockets cooperate
with the event loop automatically, so call sites do not change.
]]

local base58 = require('pay_kit.solana.base58')
local ed25519 = require('pay_kit.util.ed25519')

local M = {}
local Signer = {}
Signer.__index = Signer

-- Build a Local signer from a 64-byte secret-key string (Solana's
-- canonical layout: 32-byte seed || 32-byte public key). Raises on
-- wrong length so a bad key dies at construct-time, not at first
-- sign.
function M.new(secret_key_bytes)
  if type(secret_key_bytes) ~= 'string' or #secret_key_bytes ~= 64 then
    error('pay_kit.signer: secret must be a 64-byte binary string')
  end
  local public_bytes, derive_err = ed25519.derive_public(secret_key_bytes)
  if not public_bytes then error(derive_err) end
  return setmetatable({
    _secret_bytes = secret_key_bytes,
    _public_bytes = public_bytes,
    _public_base58 = base58.encode(public_bytes),
    _is_demo = false,
  }, Signer)
end

function Signer:pubkey()
  return self._public_base58
end

-- Sign raw message bytes. Returns a 64-byte detached Ed25519
-- signature on success or `(nil, err)` on backend failure.
function Signer:sign(message)
  return ed25519.sign(self._secret_bytes, message)
end

function Signer:fee_payer()
  return true
end

function Signer:demo()
  return self._is_demo
end

-- Internal: hand back the raw 64-byte secret. Used by the MPP
-- adapter when it still funnels a JSON-array secret into the legacy
-- pay_kit.solana.local_signer for the cosign-transaction path.
function Signer:_secret_key_bytes()
  return self._secret_bytes
end

-- Internal: hand back the 32-byte public key bytes (pre-base58).
function Signer:_public_key_bytes()
  return self._public_bytes
end

-- Internal: marker for the demo singleton so the demo factory can
-- toggle `:demo()` without exposing a public setter.
function Signer:_mark_demo()
  self._is_demo = true
  return self
end

return M
