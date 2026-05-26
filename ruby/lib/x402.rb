# frozen_string_literal: true

# `solana-x402` is the x402-protocol layer of the `solana-pay-kit` gem.
# It consumes `PayCore::Solana::*` (the shared Solana primitives + JCS +
# headers + RFC 3339 + canonical error codes crate-equivalent).
#
# Layout mirrors the Rust spine at `rust/crates/x402/src/`:
#
#   lib/x402.rb                                  -> lib.rs (umbrella)
#   lib/x402/constants.rb                        -> constants.rs
#   lib/x402/error.rb                            -> error.rs
#   lib/x402/protocol/schemes/exact/types.rb     -> protocol/schemes/exact/types.rs
#   lib/x402/protocol/schemes/exact/verify.rb    -> protocol/schemes/exact/verify.rs
#   lib/x402/server/exact.rb                     -> server/exact.rs
#   bin/x402-interop-server                      -> bin/interop_server.rs
#
# Ruby is server-only: no client surface is exposed.

require_relative "pay_core"

require_relative "x402/constants"
require_relative "x402/error"
require_relative "x402/protocol/schemes/exact/types"
require_relative "x402/protocol/schemes/exact/verify"
require_relative "x402/server/exact"

module X402
  module Protocol
    module Schemes
    end
  end

  module Server
  end
end
