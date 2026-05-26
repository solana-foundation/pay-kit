# frozen_string_literal: true

# PayCore is the shared low-level layer for the `solana-pay-kit` gem:
# Solana primitives (Base58, Mints, Programs, CAIP-2, PublicKey, ATA,
# Transaction codec, RPC), JCS RFC 8785, RFC 7235 auth-param parsing,
# RFC 3339 date-time parsing, base64url, and the canonical L6 error
# codes. Both `solana-mpp` (under the `Mpp` module) and `solana-x402`
# (under the `X402` module) consume PayCore directly. Mirrors the
# `solana-pay-core` crate from the Rust spine.

require_relative "pay_core/base64_url"
require_relative "pay_core/json"
require_relative "pay_core/rfc3339_parser"
require_relative "pay_core/headers"
require_relative "pay_core/error_codes"

require_relative "pay_core/solana/base58"
require_relative "pay_core/solana/programs"
require_relative "pay_core/solana/caip2"
require_relative "pay_core/solana/mints"
require_relative "pay_core/solana/public_key"
require_relative "pay_core/solana/ata"
require_relative "pay_core/solana/account"
require_relative "pay_core/solana/transaction"
require_relative "pay_core/solana/rpc"

module PayCore
  module Solana
  end
end
