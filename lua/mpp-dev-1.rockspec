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
}
build = {
  type = "builtin",
  modules = {
    ["mpp"] = "mpp/init.lua",
    ["mpp.error"] = "mpp/error.lua",
    ["mpp.expires"] = "mpp/expires.lua",
    ["mpp.protocol.core.challenge"] = "mpp/protocol/core/challenge.lua",
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
    ["mpp.solana.rpc"] = "mpp/solana/rpc.lua",
    ["mpp.store"] = "mpp/store.lua",
    ["mpp.util.base64url"] = "mpp/util/base64url.lua",
    ["mpp.util.bit"] = "mpp/util/bit.lua",
    ["mpp.util.crypto"] = "mpp/util/crypto.lua",
    ["mpp.util.json"] = "mpp/util/json.lua",
    ["mpp.util.uint"] = "mpp/util/uint.lua",
  },
}
