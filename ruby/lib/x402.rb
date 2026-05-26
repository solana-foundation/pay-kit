# frozen_string_literal: true

# `solana-x402` is the x402-protocol layer of the `solana-pay-kit` gem.
# It consumes `PayCore::Solana::*` (the shared Solana primitives + JCS +
# headers + RFC 3339 + canonical error codes crate-equivalent).
#
# This PR ships the interop fixture under `X402::Interop` only; the
# production x402 server surface is intentionally out of scope here and
# will be added in a follow-up. The interop modules live under
# `x402/interop/` so production application code never accidentally
# pulls in fixture-only RPC, signing, or env-var wiring.

require_relative "pay_core"

require_relative "x402/interop/exact"
require_relative "x402/interop/server"

module X402
  module Interop
  end
end
