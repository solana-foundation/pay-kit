# frozen_string_literal: true

module PayCore
  module Solana
    # Canonical Solana program IDs shared across solana-mpp and solana-x402.
    # Centralising them here prevents either layer from redeclaring program
    # constants. Mirrors the Rust spine constants in
    # `rust/crates/core/src/solana/programs.rs`.
    module Programs
      SYSTEM_PROGRAM = "11111111111111111111111111111111"
      TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
      TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
      ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
      MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
      COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
      # Lighthouse is x402-protocol-specific (assertion verification) but
      # placed here so the address lives in exactly one location across the
      # gem. See
      # https://github.com/Jac0xb/lighthouse.
      LIGHTHOUSE_PROGRAM = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
    end
  end
end
