--[[
Ed25519 crypto backend abstraction.

Two backends, picked at module load time:

1. lua-resty-openssl (preferred): FFI binding to OpenSSL's EVP_PKEY
   Ed25519 path. Bundled with Kong 3.x (kong-latest.rockspec pins
   1.5.1), available via luarocks on APISIX / OpenResty. No system
   libsodium needed.

2. luasodium (fallback): the legacy `pay_kit.solana.local_signer`
   backend. Kept so callers on plain LuaJIT environments without
   OpenResty/Kong still get a working signer. The Ruby/Rust SDKs
   both moved off libsodium for the same reason - it is an extra
   system dependency that operators do not have by default.

The public surface mirrors the cross-SDK abstraction:

  ed25519.sign(secret_key_bytes_64, message) -> (signature_64, err)
  ed25519.verify(public_key_bytes_32, message, signature_64) -> (bool, err)
  ed25519.derive_public(secret_key_bytes_64) -> (pubkey_32_bytes, err)
  ed25519.backend() -> "openssl" | "luasodium" | "none"

`backend()` is exposed for diagnostics (logged at configure time so
operators can tell which crypto path is hot).
]]

local M = {}

-- PKCS#8 v1 Ed25519 private key envelope. The 16-byte prefix wraps a
-- 32-byte seed into the DER form `resty.openssl.pkey.new` accepts.
-- Constants from RFC 8410 + OpenSSL EVP_PKEY_new_raw_private_key.
local PKCS8_PREFIX = '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
local SPKI_PREFIX  = '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'  -- public-key DER prefix

local backend
local ssl_pkey
local sodium

-- Detect backend at load time. We try openssl first; if it fails to
-- load OR fails to sign a smoke message, we fall back to luasodium.
local function try_load_openssl()
  local ok, mod = pcall(require, 'resty.openssl.pkey')
  if not ok then return false end
  -- Smoke test: load a fixed seed and sign. Detects the macOS
  -- "libcrypto not preloaded" failure mode early so callers see the
  -- fallback take over before any real work happens.
  local seed = string.rep('\7', 32)
  local sk, _ = mod.new(PKCS8_PREFIX .. seed, {format = 'DER', type = 'pr'})
  if not sk then return false end
  local sig, _ = sk:sign('smoke')
  if not sig or #sig ~= 64 then return false end
  ssl_pkey = mod
  return true
end

local function try_load_sodium()
  local ok, mod = pcall(require, 'luasodium')
  if not ok then return false end
  sodium = mod
  return true
end

if try_load_openssl() then
  backend = 'openssl'
elseif try_load_sodium() then
  backend = 'luasodium'
else
  backend = 'none'
end

function M.backend() return backend end

-- --- openssl backend ------------------------------------------------

local function openssl_sign(secret_64, message)
  local seed = secret_64:sub(1, 32)
  local sk, err = ssl_pkey.new(PKCS8_PREFIX .. seed, {format = 'DER', type = 'pr'})
  if not sk then return nil, 'pay_kit: openssl pkey.new: ' .. tostring(err) end
  local sig, sign_err = sk:sign(message)
  if not sig then return nil, 'pay_kit: openssl sign: ' .. tostring(sign_err) end
  return sig
end

local function openssl_verify(public_32, message, signature)
  local pk, err = ssl_pkey.new(SPKI_PREFIX .. public_32, {format = 'DER', type = 'pu'})
  if not pk then return nil, 'pay_kit: openssl pubkey load: ' .. tostring(err) end
  local ok, verr = pk:verify(signature, message)
  if verr then return nil, 'pay_kit: openssl verify: ' .. tostring(verr) end
  return ok
end

-- --- luasodium backend ----------------------------------------------

local function sodium_sign(secret_64, message)
  local ok, sig = pcall(function()
    return sodium.crypto_sign_ed25519_detached(message, secret_64)
  end)
  if not ok then return nil, 'pay_kit: luasodium sign: ' .. tostring(sig) end
  return sig
end

local function sodium_verify(public_32, message, signature)
  local ok, res = pcall(function()
    return sodium.crypto_sign_ed25519_verify_detached(signature, message, public_32)
  end)
  if not ok then return nil, 'pay_kit: luasodium verify: ' .. tostring(res) end
  return res and true or false
end

local function sodium_generate()
  local pk, sk = sodium.crypto_sign_ed25519_keypair()
  if not pk or not sk then
    return nil, 'pay_kit: luasodium keypair generation failed'
  end
  return sk
end

-- --- public surface -------------------------------------------------

function M.sign(secret_64, message)
  if type(secret_64) ~= 'string' or #secret_64 ~= 64 then
    return nil, 'pay_kit: ed25519.sign: secret must be 64 bytes'
  end
  if type(message) ~= 'string' then
    return nil, 'pay_kit: ed25519.sign: message must be a string'
  end
  if backend == 'openssl' then return openssl_sign(secret_64, message) end
  if backend == 'luasodium' then return sodium_sign(secret_64, message) end
  return nil, 'pay_kit: no Ed25519 backend available (install lua-resty-openssl or luasodium)'
end

function M.verify(public_32, message, signature)
  if type(public_32) ~= 'string' or #public_32 ~= 32 then
    return nil, 'pay_kit: ed25519.verify: public key must be 32 bytes'
  end
  if type(signature) ~= 'string' or #signature ~= 64 then
    return nil, 'pay_kit: ed25519.verify: signature must be 64 bytes'
  end
  if backend == 'openssl' then return openssl_verify(public_32, message, signature) end
  if backend == 'luasodium' then return sodium_verify(public_32, message, signature) end
  return nil, 'pay_kit: no Ed25519 backend available'
end

-- Derive the 32-byte public key half of a Solana 64-byte secret. The
-- secret already contains the public key (Solana's canonical layout
-- is `seed || pubkey`), so this is just a substring read in either
-- backend.
function M.derive_public(secret_64)
  if type(secret_64) ~= 'string' or #secret_64 ~= 64 then
    return nil, 'pay_kit: ed25519.derive_public: secret must be 64 bytes'
  end
  return secret_64:sub(33, 64)
end

-- Generate a fresh keypair (returns the 64-byte Solana secret).
-- Only available via luasodium today; openssl-only environments
-- raise. Test-only - production callers load from files or env.
function M.generate()
  if sodium then return sodium_generate() end
  return nil, 'pay_kit: ed25519.generate: luasodium not available ' ..
    '(openssl backend cannot emit Solana 64-byte secret without seed derivation)'
end

return M
