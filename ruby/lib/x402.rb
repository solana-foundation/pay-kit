# frozen_string_literal: true

# `solana-x402` is the x402-protocol implementation layer of the
# `solana-pay-kit` gem. It consumes `PayCore::Solana::*` (the shared
# Solana primitives + JCS + headers + RFC 3339 + canonical error codes
# crate-equivalent) and exposes the exact-scheme client and server
# entry points.

require_relative "pay_core"

require_relative "x402/exact"
require_relative "x402/client"
require_relative "x402/server"

module X402
end
