package = "mpp"
version = "dev-1"
source = {
  url = "git+https://github.com/solana-foundation/mpp-sdk.git",
}
description = {
  summary = "Solana payment method for the Machine Payments Protocol (MPP), Lua server SDK.",
  detailed = [[
    Lua implementation of the MPP charge server intent. Issues 402 Payment
    Required challenges, verifies credentials against a Solana-backed payment
    flow, and orchestrates settlement via a transport-agnostic JSON-RPC
    client. Mirrors the Rust reference at github.com/solana-foundation/mpp-sdk
    rust/.
  ]],
  homepage = "https://github.com/solana-foundation/mpp-sdk",
  license = "MIT",
}
dependencies = {
  "lua >= 5.1, < 5.5",
  "luasocket >= 3.0",
  "luasodium >= 2.0",
  -- Required by mpp.solana.rpc_transport for the documented HTTPS RPC URLs.
  "luasec >= 1.3",
}
build = {
  type = "builtin",
  modules = {
    ["mpp"] = "mpp/init.lua",
    ["mpp.error"] = "mpp/error.lua",
    ["mpp.expires"] = "mpp/expires.lua",
    ["mpp.methods.solana.ata"] = "mpp/methods/solana/ata.lua",
    ["mpp.methods.solana.instructions"] = "mpp/methods/solana/instructions.lua",
    ["mpp.methods.solana.signer"] = "mpp/methods/solana/signer.lua",
    ["mpp.methods.solana.transaction"] = "mpp/methods/solana/transaction.lua",
    ["mpp.methods.solana.verifier"] = "mpp/methods/solana/verifier.lua",
    ["mpp.protocol.core.challenge"] = "mpp/protocol/core/challenge.lua",
    ["mpp.protocol.core.error_codes"] = "mpp/protocol/core/error_codes.lua",
    ["mpp.protocol.core.headers"] = "mpp/protocol/core/headers.lua",
    ["mpp.protocol.core.types"] = "mpp/protocol/core/types.lua",
    ["mpp.protocol.intents.charge"] = "mpp/protocol/intents/charge.lua",
    ["mpp.protocol.solana"] = "mpp/protocol/solana.lua",
    ["mpp.server"] = "mpp/server/init.lua",
    ["mpp.server.charge_handler"] = "mpp/server/charge_handler.lua",
    ["mpp.server.html"] = "mpp/server/html.lua",
    ["mpp.server.html_assets.gen"] = "mpp/server/html_assets/gen.lua",
    ["mpp.server.network_check"] = "mpp/server/network_check.lua",
    ["mpp.server.solana_verify"] = "mpp/server/solana_verify.lua",
    ["mpp.server.store_shared_dict"] = "mpp/server/store_shared_dict.lua",
    ["mpp.solana.rpc"] = "mpp/solana/rpc.lua",
    ["mpp.solana.rpc_transport"] = "mpp/solana/rpc_transport.lua",
    ["mpp.solana.rpc_transport_resty"] = "mpp/solana/rpc_transport_resty.lua",
    ["mpp.store"] = "mpp/store.lua",
    ["mpp.util.base58"] = "mpp/util/base58.lua",
    ["mpp.util.base64_std"] = "mpp/util/base64_std.lua",
    ["mpp.util.base64url"] = "mpp/util/base64url.lua",
    ["mpp.util.bit"] = "mpp/util/bit.lua",
    ["mpp.util.crypto"] = "mpp/util/crypto.lua",
    ["mpp.util.json"] = "mpp/util/json.lua",
    ["mpp.util.uint"] = "mpp/util/uint.lua",
  },
}
