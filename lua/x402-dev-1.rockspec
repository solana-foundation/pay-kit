package = "x402"
version = "dev-1"
source = {
  url = "git+https://github.com/solana-foundation/mpp-sdk.git",
}
description = {
  summary = "Solana x402 exact server adapter for the Machine Payments Protocol (MPP), Lua server SDK.",
  detailed = [[
    Lua implementation of the x402 `exact` server-side adapter. Mirrors the
    Rust reference at github.com/solana-foundation/mpp-sdk rust/crates/x402/
    and the cross-language exact server matrix maintained by the x402-sdk
    project. Server-only for this milestone.
  ]],
  homepage = "https://github.com/solana-foundation/mpp-sdk",
  license = "Apache-2.0",
}
dependencies = {
  "lua >= 5.4",
  "luasocket",
  "luasec",
  "dkjson",
  "luasodium",
  "luazen",
}
build = {
  type = "builtin",
  modules = {},
  install = {
    bin = {
      ["x402-interop-server"] = "x402/bin/interop-server.lua",
    },
  },
}
