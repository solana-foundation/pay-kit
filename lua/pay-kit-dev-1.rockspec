package = 'pay-kit'
version = 'dev-1'
source = {
  url = 'git+https://github.com/solana-foundation/pay-kit.git',
}
description = {
  summary = 'Server-side PayKit SDK for Lua (x402 + MPP).',
  detailed = [[
    Lua / LuaJIT 2.1 implementation of the PayKit umbrella surface.
    One module, two protocols underneath: x402 (exact scheme on
    Solana) and the Machine Payments Protocol. Boots inside any
    Lua host that can speak HTTP; sibling plugin rockspecs
    (kong-plugin-pay-kit, apisix-plugin-pay-kit) wrap the same
    core for Kong and APISIX. Server-only; clients live in the
    TypeScript, Rust, Go, Python, Ruby, Kotlin, and Swift packages.
  ]],
  homepage = 'https://github.com/solana-foundation/pay-kit',
  license = 'MIT',
}
dependencies = {
  'lua >= 5.1, < 5.5',
  'luasocket >= 3.0',
  'lua-resty-openssl >= 0.8',
  'luasodium >= 2.0',
  'luasec >= 1.3',
  'lua-cjson >= 2.1',
}
build = {
  type = 'builtin',
  modules = {
    ['pay_kit']                          = 'pay_kit/init.lua',
    ['pay_kit.errors']                   = 'pay_kit/errors.lua',
    ['pay_kit.kms']                      = 'pay_kit/kms.lua',
    ['pay_kit.preflight']                = 'pay_kit/preflight.lua',
    ['pay_kit.signer']                   = 'pay_kit/signer.lua',
    ['pay_kit.signer.demo']              = 'pay_kit/signer/demo.lua',
    ['pay_kit.signer.local']             = 'pay_kit/signer/local.lua',
    ['pay_kit.store']                    = 'pay_kit/store.lua',

    -- Solana-flavoured helpers: base58 + cosocket RPC + tx cosign.
    ['pay_kit.solana.base58']            = 'pay_kit/solana/base58.lua',
    ['pay_kit.solana.rpc']               = 'pay_kit/solana/rpc.lua',
    ['pay_kit.solana.tx_cosign']         = 'pay_kit/solana/tx_cosign.lua',

    -- Generic util surface.
    ['pay_kit.util.base64url']           = 'pay_kit/util/base64url.lua',
    ['pay_kit.util.json']                = 'pay_kit/util/json.lua',
    ['pay_kit.util.crypto']              = 'pay_kit/util/crypto.lua',
    ['pay_kit.util.ed25519']             = 'pay_kit/util/ed25519.lua',

    -- Protocol adapters, split per protocol then per scheme/intent.
    ['pay_kit.protocols.mpp']                  = 'pay_kit/protocols/mpp/init.lua',
    ['pay_kit.protocols.x402']                 = 'pay_kit/protocols/x402/init.lua',
    ['pay_kit.protocols.x402.exact.verify']    = 'pay_kit/protocols/x402/exact/verify.lua',

    -- Internal implementation modules (callers use the umbrella).
    ['pay_kit.internal.config']     = 'pay_kit/internal/config.lua',
    ['pay_kit.internal.dispatcher'] = 'pay_kit/internal/dispatcher.lua',
    ['pay_kit.internal.fee']        = 'pay_kit/internal/fee.lua',
    ['pay_kit.internal.gate']       = 'pay_kit/internal/gate.lua',
    ['pay_kit.internal.operator']   = 'pay_kit/internal/operator.lua',
    ['pay_kit.internal.price']      = 'pay_kit/internal/price.lua',
    ['pay_kit.internal.registry']   = 'pay_kit/internal/registry.lua',
  },
}
