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

      # Testnet stablecoin mints alias the devnet addresses, matching the
      # Rust spine `rust/crates/mpp/src/protocol/solana.rs:19-26`
      # (USDC_TESTNET == USDC_DEVNET, USDG_TESTNET == USDG_DEVNET,
      # PYUSD_TESTNET == PYUSD_DEVNET). Without the explicit "testnet"
      # entry, `resolve(currency, "testnet")` fell back to the MAINNET mint,
      # so a testnet-configured server verified SPL transferChecked against
      # the mainnet mint while a spec/rust client built against the devnet
      # mint.
      USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
      USDG_DEVNET = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
      PYUSD_DEVNET = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"

      MINTS = {
        "USDC" => {
          "devnet" => USDC_DEVNET,
          "testnet" => USDC_DEVNET,
          "mainnet" => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        },
        "USDT" => {
          "mainnet" => "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        },
        "USDG" => {
          "devnet" => USDG_DEVNET,
          "testnet" => USDG_DEVNET,
          "mainnet" => "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
        },
        "PYUSD" => {
          "devnet" => PYUSD_DEVNET,
          "testnet" => PYUSD_DEVNET,
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
      #
      # SAFETY (audit #28): this resolves the token program from the static
      # stablecoin table ONLY. Known stablecoins (including Token-2022 ones:
      # PYUSD/USDG/CASH) resolve correctly. An ARBITRARY mint address that is
      # not in the table is NOT recognised here — callers that accept arbitrary
      # mints MUST NOT rely on this method's legacy-Token default. Use
      # `known_currency?` to gate, and have the caller require an explicit
      # on-chain-resolved `tokenProgram` (or reject) for unknown mints. See
      # `PayKit::Protocols::Mpp::Protocol::Solana::ChargeMethod`.
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

      # True when `currency` is a known symbol (or SOL), or a known stablecoin
      # mint address. False for an arbitrary, unrecognised mint address — for
      # which the static `token_program_for` legacy-Token default is NOT safe
      # to trust (audit #28). Used to decide whether the token program can be
      # resolved from the table or must be supplied/resolved on-chain.
      def known_currency?(currency, network)
        !symbol_for(currency, network).nil?
      end

      # Look up the decimals for a known mint symbol or address. Falls back
      # to 6 (the common SPL stablecoin precision) for unknown tokens.
      def decimals_for(currency, network)
        DECIMALS[symbol_for(currency, network)] || DEFAULT_DECIMALS
      end
    end
  end
end
