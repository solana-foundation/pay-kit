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
    -- Umbrella + sub-modules.
    ['resty.pay_kit']              = 'resty/pay_kit/init.lua',
    ['resty.pay_kit.config']       = 'resty/pay_kit/config.lua',
    ['resty.pay_kit.dispatcher']   = 'resty/pay_kit/dispatcher.lua',
    ['resty.pay_kit.errors']       = 'resty/pay_kit/errors.lua',
    ['resty.pay_kit.fee']          = 'resty/pay_kit/fee.lua',
    ['resty.pay_kit.gate']         = 'resty/pay_kit/gate.lua',
    ['resty.pay_kit.kms']          = 'resty/pay_kit/kms.lua',
    ['resty.pay_kit.operator']     = 'resty/pay_kit/operator.lua',
    ['resty.pay_kit.price']        = 'resty/pay_kit/price.lua',
    ['resty.pay_kit.registry']     = 'resty/pay_kit/registry.lua',
    ['resty.pay_kit.signer']       = 'resty/pay_kit/signer.lua',
    ['resty.pay_kit.signer.demo']  = 'resty/pay_kit/signer/demo.lua',
    ['resty.pay_kit.signer.local'] = 'resty/pay_kit/signer/local.lua',
    ['resty.pay_kit.store']        = 'resty/pay_kit/store.lua',
    ['resty.pay_kit.util.ed25519'] = 'resty/pay_kit/util/ed25519.lua',
    ['resty.pay_kit.schemes.mpp']  = 'resty/pay_kit/schemes/mpp.lua',
    ['resty.pay_kit.schemes.x402'] = 'resty/pay_kit/schemes/x402.lua',
  },
}
