rockspec_format = '3.0'
package = 'pay-kit'
version = 'dev-1'
source = {
  url = 'git+https://github.com/solana-foundation/pay-kit.git',
}
description = {
  summary = 'Building blocks for Agentic payments (x402, MPP, AP2)',
  detailed = [[
    Lua / LuaJIT 2.1 implementation of the PayKit umbrella surface.
    One module, two protocols underneath: x402 (exact scheme on
    Solana) and the Machine Payments Protocol. Boots inside any
    Lua host that can speak HTTP; sibling plugin rockspecs
    (kong-plugin-pay-kit, apisix-plugin-pay-kit) wrap the same
    core for Kong and APISIX. Server-only; clients live in the
    TypeScript, Rust, Go, Python, Ruby, Kotlin, and Swift packages.
  ]],
  homepage = 'https://github.com/solana-foundation/pay-kit/tree/main/lua',
  issues_url = 'https://github.com/solana-foundation/pay-kit/issues',
  maintainer = 'Solana Foundation',
  license = 'MIT',
  labels = {
    'solana', 'payments', 'x402', 'mpp', 'ap2',
    'agentic', 'stablecoin', 'usdc', 'openresty',
  },
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
    -- Umbrella surface
    ['pay_kit']                          = 'pay_kit/init.lua',
    ['pay_kit.errors']                   = 'pay_kit/errors.lua',
    ['pay_kit.kms']                      = 'pay_kit/kms.lua',
    ['pay_kit.preflight']                = 'pay_kit/preflight.lua',
    ['pay_kit.signer']                   = 'pay_kit/signer.lua',
    ['pay_kit.signer.demo']              = 'pay_kit/signer/demo.lua',
    ['pay_kit.signer.local']             = 'pay_kit/signer/local.lua',
    ['pay_kit.store']                    = 'pay_kit/store.lua',

    -- Solana primitives
    ['pay_kit.solana.ata']               = 'pay_kit/solana/ata.lua',
    ['pay_kit.solana.base58']            = 'pay_kit/solana/base58.lua',
    ['pay_kit.solana.instructions']      = 'pay_kit/solana/instructions.lua',
    ['pay_kit.solana.local_signer']      = 'pay_kit/solana/local_signer.lua',
    ['pay_kit.solana.mints']             = 'pay_kit/solana/mints.lua',
    ['pay_kit.solana.network_check']     = 'pay_kit/solana/network_check.lua',
    ['pay_kit.solana.rpc']               = 'pay_kit/solana/rpc.lua',
    ['pay_kit.solana.rpc_transport']     = 'pay_kit/solana/rpc_transport.lua',
    ['pay_kit.solana.rpc_transport_resty'] = 'pay_kit/solana/rpc_transport_resty.lua',
    ['pay_kit.solana.transaction']       = 'pay_kit/solana/transaction.lua',
    ['pay_kit.solana.tx_cosign']         = 'pay_kit/solana/tx_cosign.lua',
    ['pay_kit.solana.verifier']          = 'pay_kit/solana/verifier.lua',

    -- Generic util surface
    ['pay_kit.util.base64_std']          = 'pay_kit/util/base64_std.lua',
    ['pay_kit.util.base64url']           = 'pay_kit/util/base64url.lua',
    ['pay_kit.util.bit']                 = 'pay_kit/util/bit.lua',
    ['pay_kit.util.crypto']              = 'pay_kit/util/crypto.lua',
    ['pay_kit.util._mpp_crypto']         = 'pay_kit/util/_mpp_crypto.lua',
    ['pay_kit.util.ed25519']             = 'pay_kit/util/ed25519.lua',
    ['pay_kit.util.json']                = 'pay_kit/util/json.lua',
    ['pay_kit.util.uint']                = 'pay_kit/util/uint.lua',

    -- Protocol-agnostic core (wire format + canonical error codes)
    ['pay_kit.protocol.core.challenge']    = 'pay_kit/protocol/core/challenge.lua',
    ['pay_kit.protocol.core.error_codes']  = 'pay_kit/protocol/core/error_codes.lua',
    ['pay_kit.protocol.core.headers']      = 'pay_kit/protocol/core/headers.lua',
    ['pay_kit.protocol.core.types']        = 'pay_kit/protocol/core/types.lua',

    -- Protocol adapters: per-protocol then per-scheme/intent
    ['pay_kit.protocols.mpp']              = 'pay_kit/protocols/mpp/init.lua',
    ['pay_kit.protocols.mpp.charge']       = 'pay_kit/protocols/mpp/charge.lua',
    ['pay_kit.protocols.mpp.error']        = 'pay_kit/protocols/mpp/error.lua',
    ['pay_kit.protocols.mpp.expires']      = 'pay_kit/protocols/mpp/expires.lua',
    ['pay_kit.protocols.mpp.store']        = 'pay_kit/protocols/mpp/store.lua',
    ['pay_kit.protocols.mpp.server']                  = 'pay_kit/protocols/mpp/server/init.lua',
    ['pay_kit.protocols.mpp.server.charge_handler']   = 'pay_kit/protocols/mpp/server/charge_handler.lua',
    ['pay_kit.protocols.mpp.server.html']             = 'pay_kit/protocols/mpp/server/html.lua',
    ['pay_kit.protocols.mpp.server.html_assets.gen']  = 'pay_kit/protocols/mpp/server/html_assets/gen.lua',
    ['pay_kit.protocols.mpp.server.solana_verify']    = 'pay_kit/protocols/mpp/server/solana_verify.lua',
    ['pay_kit.protocols.mpp.server.store_shared_dict'] = 'pay_kit/protocols/mpp/server/store_shared_dict.lua',
    ['pay_kit.protocols.x402']                = 'pay_kit/protocols/x402/init.lua',
    ['pay_kit.protocols.x402.exact.verify']   = 'pay_kit/protocols/x402/exact/verify.lua',

    -- Internal implementation modules
    ['pay_kit.internal.config']     = 'pay_kit/internal/config.lua',
    ['pay_kit.internal.dispatcher'] = 'pay_kit/internal/dispatcher.lua',
    ['pay_kit.internal.fee']        = 'pay_kit/internal/fee.lua',
    ['pay_kit.internal.gate']       = 'pay_kit/internal/gate.lua',
    ['pay_kit.internal.operator']   = 'pay_kit/internal/operator.lua',
    ['pay_kit.internal.price']      = 'pay_kit/internal/price.lua',
    ['pay_kit.internal.registry']   = 'pay_kit/internal/registry.lua',
  },
}
