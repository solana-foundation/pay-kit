--[[
Crypto wrapper. Public surface per issue #140 Layers section.

Exposes the two crypto primitives PayKit's schemes depend on, behind
a stable interface that swaps the underlying backend (lua-resty-openssl
when available, luasodium / pure-Lua fallback otherwise):

- `crypto.ed25519.sign(secret_64, message) -> (sig_64, err)`
- `crypto.ed25519.verify(public_32, message, sig_64) -> (bool, err)`
- `crypto.ed25519.derive_public(secret_64) -> (public_32, err)`
- `crypto.ed25519.backend() -> "openssl" | "luasodium" | "none"`
- `crypto.hmac_sha256(key, message) -> raw 32-byte digest`
- `crypto.constant_time_equal(a, b) -> bool`

The Ed25519 surface lives in `pay_kit.util.ed25519`; this
module re-exports it under the design-named path so a single
`require('pay_kit.util.crypto')` brings every crypto primitive
along. HMAC + constant-time-equal stay on the legacy
`pay_kit.util._mpp_crypto` (pure Lua; will swap to `resty.openssl.mac` when
the OpenResty crypto migration lands).
]]

local M = {}

M.ed25519 = require('pay_kit.util.ed25519')

local mpp_crypto = require('pay_kit.util._mpp_crypto')
M.hmac_sha256          = mpp_crypto.hmac_sha256
M.constant_time_equal  = mpp_crypto.constant_eq

return M
