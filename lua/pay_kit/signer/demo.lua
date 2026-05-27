--[[
Demo signer.

A package-shipped Ed25519 keypair used for zero-config boot. The
secret is in the source so anyone reading the gem knows not to ship
it to production. `pay_kit.configure` refuses to start with
this signer on `network = "solana_mainnet"`.

The 64-byte secret + base58 pubkey match the Ruby gem's
`PayKit::Signer::Demo` (ruby/lib/pay_kit/signer/demo.rb) so the two
SDKs boot under the same demo identity, useful when one process
talks to another during local development.
]]

local local_signer = require('pay_kit.signer.local')

local M = {}

-- 64-byte secret (32-byte seed || 32-byte public key), as a sequence
-- of byte values. Same bytes as `PayKit::Signer::Demo::SECRET_BYTES`
-- in the Ruby SDK; do not edit without regenerating the pair.
M.SECRET_BYTES = {
  26, 61, 117, 192, 9, 232, 24, 51, 89, 135, 105, 182, 47, 9, 83, 244,
  11, 214, 85, 170, 227, 83, 170, 26, 55, 129, 58, 114, 89, 160, 195, 51,
  138, 209, 127, 35, 54, 41, 202, 166, 199, 166, 97, 238, 181, 63, 254, 185,
  45, 16, 174, 102, 250, 198, 30, 191, 232, 236, 147, 167, 41, 178, 151, 26,
}

M.PUBKEY = 'ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq'

M.WARNING_MESSAGE =
  'pay_kit: demo signer is in use; this keypair is published in the gem ' ..
  'source and MUST NOT be used in production. configure() refuses to ' ..
  'start when this signer is combined with network = "solana_mainnet".'

-- Private state guarded by closures so tests can reset without
-- touching the cached singleton from the public surface.
local instance
local warned

local function secret_bytes_as_string()
  local bytes = {}
  for i = 1, #M.SECRET_BYTES do
    bytes[i] = string.char(M.SECRET_BYTES[i])
  end
  return table.concat(bytes)
end

-- Resolve a logger that prints once at first :instance() call. Falls
-- back to print() when ngx is absent (pure-Lua mode).
local function warn_once()
  if warned then return end
  warned = true
  local ngx_ref = rawget(_G, 'ngx')
  if ngx_ref and ngx_ref.log and ngx_ref.WARN then
    ngx_ref.log(ngx_ref.WARN, M.WARNING_MESSAGE)
  else
    io.stderr:write('[pay_kit] WARN: ' .. M.WARNING_MESSAGE .. '\n')
  end
end

-- Return the cached demo signer. First call also emits the boot
-- warning. Subsequent calls are silent. The returned signer's
-- :demo() returns true so configure() can enforce the mainnet
-- refusal rule.
function M.instance()
  warn_once()
  if instance ~= nil then
    return instance
  end
  instance = local_signer.new(secret_bytes_as_string()):_mark_demo()
  return instance
end

-- Test-only: forget the singleton and the warn-once flag. Production
-- code should never need this; the demo-signer suite calls it to
-- exercise the "warn fires exactly once" contract per process.
function M.reset_for_tests()
  instance = nil
  warned = false
end

return M
