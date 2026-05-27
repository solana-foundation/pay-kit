package = 'lua-resty-pay-kit'
version = 'dev-1'
source = {
  url = 'git+https://github.com/solana-foundation/pay-kit.git',
}
description = {
  summary = 'Server-side PayKit SDK for Lua / OpenResty (x402 + MPP).',
  detailed = [[
    Lua / LuaJIT 2.1 implementation of the PayKit umbrella surface
    (issue #140). One module, two protocols underneath: x402 (exact
    scheme on Solana) and the Machine Payments Protocol. Drops into
    `access_by_lua_*` blocks; ships Kong + APISIX plugins as thin
    wrappers in sibling rockspecs (kong-plugin-pay-kit,
    apisix-plugin-pay-kit). Server-only; clients live in the
    TypeScript, Rust, Go, Python, Ruby, Kotlin, and Swift packages.
  ]],
  homepage = 'https://github.com/solana-foundation/pay-kit',
  license = 'MIT',
}
dependencies = {
  'lua >= 5.1, < 5.5',
  'luasocket >= 3.0',
  'lua-resty-openssl >= 0.8',
  -- luasodium kept as fallback for plain LuaJIT environments without
  -- OpenResty / OpenSSL. lua-resty-openssl is the production path;
  -- crypto backend picks at module load.
  'luasodium >= 2.0',
  'luasec >= 1.3',
  'lua-cjson >= 2.1',
}
build = {
  type = 'builtin',
  modules = {
    -- Umbrella + public surface (matches issue #140 Layers section).
    ['resty.pay_kit']                   = 'resty/pay_kit/init.lua',
    ['resty.pay_kit.errors']            = 'resty/pay_kit/errors.lua',
    ['resty.pay_kit.kms']               = 'resty/pay_kit/kms.lua',
    ['resty.pay_kit.signer']            = 'resty/pay_kit/signer.lua',
    ['resty.pay_kit.signer.demo']       = 'resty/pay_kit/signer/demo.lua',
    ['resty.pay_kit.signer.local']      = 'resty/pay_kit/signer/local.lua',
    ['resty.pay_kit.store']             = 'resty/pay_kit/store.lua',
    ['resty.pay_kit.solana.rpc']        = 'resty/pay_kit/solana/rpc.lua',
    ['resty.pay_kit.util.base58']       = 'resty/pay_kit/util/base58.lua',
    ['resty.pay_kit.util.base64url']    = 'resty/pay_kit/util/base64url.lua',
    ['resty.pay_kit.util.json']         = 'resty/pay_kit/util/json.lua',
    ['resty.pay_kit.util.crypto']       = 'resty/pay_kit/util/crypto.lua',
    ['resty.pay_kit.util.ed25519']      = 'resty/pay_kit/util/ed25519.lua',
    ['resty.pay_kit.util.tx_cosign']    = 'resty/pay_kit/util/tx_cosign.lua',
    ['resty.pay_kit.protocols.mpp']                = 'resty/pay_kit/protocols/mpp/init.lua',
    ['resty.pay_kit.protocols.x402']               = 'resty/pay_kit/protocols/x402/init.lua',
    ['resty.pay_kit.protocols.x402.exact.verify']  = 'resty/pay_kit/protocols/x402/exact/verify.lua',

    -- Internal implementation modules (not part of the public API;
    -- callers use the umbrella surface above). Listed in the rockspec
    -- so `luarocks install` lays them on disk for the umbrella to
    -- require, but `resty.pay_kit.internal.*` paths are subject to
    -- change without a deprecation cycle.
    ['resty.pay_kit.internal.config']     = 'resty/pay_kit/internal/config.lua',
    ['resty.pay_kit.internal.dispatcher'] = 'resty/pay_kit/internal/dispatcher.lua',
    ['resty.pay_kit.internal.fee']        = 'resty/pay_kit/internal/fee.lua',
    ['resty.pay_kit.internal.gate']       = 'resty/pay_kit/internal/gate.lua',
    ['resty.pay_kit.internal.operator']   = 'resty/pay_kit/internal/operator.lua',
    ['resty.pay_kit.internal.price']      = 'resty/pay_kit/internal/price.lua',
    ['resty.pay_kit.internal.registry']   = 'resty/pay_kit/internal/registry.lua',
  },
}
