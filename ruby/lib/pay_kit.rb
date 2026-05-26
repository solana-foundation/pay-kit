# frozen_string_literal: true

# `solana-pay-kit` umbrella module. Mirrors the Rust spine layout
# (solana-pay-core / solana-mpp / solana-x402 / solana-pay-kit):
#
#  -----------------------------------------------------------
# |                  solana-pay-kit                           |
#  -----------------------------------------------------------
# |   solana-mpp        |     solana-x402                     |
#  -----------------------------------------------------------
# |                  solana-pay-core                          |
#  -----------------------------------------------------------
#
# Requiring `pay_kit` loads the shared `PayCore` primitives, then both
# the `Mpp` and `X402` protocol layers, and exposes them under the
# `PayKit` umbrella for callers that prefer one entry point.

require_relative "pay_core"
require_relative "mpp"
require_relative "x402"

# Umbrella namespace re-exporting each layer under the `PayKit::*`
# alias. Callers may continue to use the bare `Mpp`, `X402`, and
# `PayCore` modules directly; `PayKit::Mpp` etc. exist for downstream
# code that wants a single canonical entry point.
module PayKit
  Core = ::PayCore
  Mpp = ::Mpp
  X402 = ::X402
end
