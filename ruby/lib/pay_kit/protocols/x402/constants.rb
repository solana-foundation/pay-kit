# frozen_string_literal: true

require "pay_core/solana/programs"

module PayKit::Protocols::X402
  # Wire-level constants shared across schemes. Mirrors the Rust spine
  # `rust/crates/x402/src/constants.rs` and the exact-scheme constants
  # block at `rust/crates/x402/src/protocol/schemes/exact/types.rs:6-12`.
  #
  # Program ID literals live in the shared `PayCore::Solana::Programs`
  # table so x402 and MPP cannot drift on canonical SPL program IDs.
  module Constants
    # --- Protocol version (spine constants.rs:7-13) -----------------------
    X402_VERSION_FIELD = "x402Version"
    X402_VERSION_V1 = 1
    X402_VERSION_V2 = 2

    # --- v1 legacy headers (spine constants.rs:16-22) ---------------------
    X402_V1_PAYMENT_HEADER = "X-PAYMENT"
    X402_V1_PAYMENT_REQUIRED_HEADER = "X-PAYMENT-REQUIRED"
    X402_V1_PAYMENT_RESPONSE_HEADER = "X-PAYMENT-RESPONSE"

    # --- v2 canonical headers (spine constants.rs:25-31) ------------------
    X402_V2_PAYMENT_HEADER = "PAYMENT-SIGNATURE"
    X402_V2_PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
    X402_V2_PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE"

    # Active aliases (spine constants.rs:40-46).
    PAYMENT_REQUIRED_HEADER = X402_V2_PAYMENT_REQUIRED_HEADER
    PAYMENT_SIGNATURE_HEADER = X402_V2_PAYMENT_HEADER
    PAYMENT_RESPONSE_HEADER = X402_V2_PAYMENT_RESPONSE_HEADER

    # --- Exact-scheme literals (spine types.rs:6-9) -----------------------
    EXACT_SCHEME = "exact"
    MAX_MEMO_BYTES = 256

    # --- Compute budget bounds (Ruby port hardening) ----------------------
    DEFAULT_COMPUTE_UNIT_LIMIT = 20_000
    DEFAULT_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 1
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000

    # --- Program IDs (sourced from PayCore::Solana::Programs) -------------
    COMPUTE_BUDGET_PROGRAM = ::PayCore::Solana::Programs::COMPUTE_BUDGET_PROGRAM
    MEMO_PROGRAM = ::PayCore::Solana::Programs::MEMO_PROGRAM
    ASSOCIATED_TOKEN_PROGRAM = ::PayCore::Solana::Programs::ASSOCIATED_TOKEN_PROGRAM
    SYSTEM_PROGRAM = ::PayCore::Solana::Programs::SYSTEM_PROGRAM
    TOKEN_2022_PROGRAM = ::PayCore::Solana::Programs::TOKEN_2022_PROGRAM
    LIGHTHOUSE_PROGRAM = ::PayCore::Solana::Programs::LIGHTHOUSE_PROGRAM
  end
end
