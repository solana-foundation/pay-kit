# frozen_string_literal: true

require_relative "programs"

module PayCore
  module Solana
    # Known stablecoin mint table and helpers for resolving mint, token
    # program, and decimals from a currency symbol. Shared by solana-mpp
    # and solana-x402; mirrors the Rust spine
    # `rust/crates/core/src/solana/mints.rs`.
    module Mints
      # Program ID re-exports for callers that historically imported them
      # from this module (kept for source-level compatibility with the
      # pre-PayCore layout). The canonical home is `PayCore::Solana::Programs`.
      TOKEN_PROGRAM = Programs::TOKEN_PROGRAM
      TOKEN_2022_PROGRAM = Programs::TOKEN_2022_PROGRAM
      SYSTEM_PROGRAM = Programs::SYSTEM_PROGRAM
      ASSOCIATED_TOKEN_PROGRAM = Programs::ASSOCIATED_TOKEN_PROGRAM
      MEMO_PROGRAM = Programs::MEMO_PROGRAM
      COMPUTE_BUDGET_PROGRAM = Programs::COMPUTE_BUDGET_PROGRAM

      MINTS = {
        "USDC" => {
          "devnet" => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
          "mainnet" => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        },
        "USDT" => {
          "mainnet" => "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        },
        "USDG" => {
          "devnet" => "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
          "mainnet" => "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
        },
        "PYUSD" => {
          "devnet" => "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
          "mainnet" => "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
        },
        "CASH" => {
          "mainnet" => "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
        }
      }.freeze

      TOKEN_2022_SYMBOLS = ["PYUSD", "USDG", "CASH"].freeze

      # Known token decimals. Every USD stablecoin in MINTS is 6; SOL is 9
      # (the native lamport precision). Unknown SPL tokens fall back to 6.
      DECIMALS = {
        "USDC" => 6,
        "USDT" => 6,
        "USDG" => 6,
        "PYUSD" => 6,
        "CASH" => 6,
        "SOL" => 9
      }.freeze
      DEFAULT_DECIMALS = 6

      module_function

      # Resolve a currency symbol or mint into a mint address.
      def resolve(currency, network)
        return nil if currency.to_s.casecmp("SOL").zero?
        return currency if currency.to_s.length >= 32

        entries = MINTS[currency.to_s.upcase]
        entries&.[](network) || entries&.[]("mainnet") || currency
      end

      # Return the default SPL token program for a currency.
      def token_program_for(currency, network)
        symbol = symbol_for(currency, network)
        TOKEN_2022_SYMBOLS.include?(symbol) ? TOKEN_2022_PROGRAM : TOKEN_PROGRAM
      end

      def symbol_for(currency, network)
        upper = currency.to_s.upcase
        return upper if MINTS.key?(upper) || upper == "SOL"

        resolved = resolve(currency, network)
        MINTS.each do |symbol, entries|
          return symbol if entries.value?(resolved)
        end
        nil
      end

      # Look up the decimals for a known mint symbol or address. Falls back
      # to 6 (the common SPL stablecoin precision) for unknown tokens.
      def decimals_for(currency, network)
        DECIMALS[symbol_for(currency, network)] || DEFAULT_DECIMALS
      end
    end
  end
end
