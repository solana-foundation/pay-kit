# frozen_string_literal: true

# The x402 protocol layer of the `solana-pay-kit` gem. It consumes
# `PayCore::Solana::*` (the shared Solana primitives + JCS + headers +
# RFC 3339 + canonical error codes crate-equivalent).
#
# Layout mirrors the Rust spine at `rust/crates/x402/src/`:
#
#   protocols/x402/constants.rb                        -> constants.rs
#   protocols/x402/error.rb                            -> error.rs
#   protocols/x402/protocol/schemes/exact/types.rb     -> protocol/schemes/exact/types.rs
#   protocols/x402/protocol/schemes/exact/verify.rb    -> protocol/schemes/exact/verify.rs
#   protocols/x402/server/exact.rb                     -> server/exact.rs
#
# Ruby is server-only: no client surface is exposed.

require_relative "../../../pay_core"

require_relative "constants"
require_relative "error"
require_relative "protocol/schemes/exact/types"
require_relative "protocol/schemes/exact/verify"
require_relative "server/exact"

module PayKit::Protocols::X402
  module Protocol
    module Schemes
    end
  end

  module Server
  end
end
