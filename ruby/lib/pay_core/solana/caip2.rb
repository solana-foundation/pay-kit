# frozen_string_literal: true

module PayCore
  module Solana
    # CAIP-2 network identifiers for Solana clusters. Used on the x402 wire
    # protocol where networks are referenced by their chain-agnostic ID
    # (see https://chainagnostic.org/CAIPs/caip-2 and the Solana CAIP-2
    # entry). Centralised here so x402 client + server do not duplicate
    # the devnet string literal.
    module Caip2
      MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
      DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
      TESTNET = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"

      # Legacy plain SVM network slugs used on the x402 EXACT v1 wire, where
      # networks are referenced by name rather than CAIP-2 ID. Mirrors the
      # Rust spine `SOLANA_NETWORK`/`SOLANA_DEVNET`/`SOLANA_TESTNET` literals
      # (rust/crates/x402/src/constants.rs:4 + protocol/schemes/exact/types.rs).
      LEGACY_MAINNET = "solana"
      LEGACY_DEVNET = "solana-devnet"
      LEGACY_TESTNET = "solana-testnet"

      ALL = {
        "mainnet" => MAINNET,
        "devnet" => DEVNET,
        "testnet" => TESTNET
      }.freeze

      module_function

      # Resolve a friendly network name ("devnet") to its CAIP-2 ID, or
      # return the input unchanged if it already looks like a CAIP-2 ID.
      def resolve(network)
        return network if network.to_s.start_with?("solana:")

        ALL[network.to_s] || network
      end

      # Normalize ANY cluster/network identifier to its canonical CAIP-2 ID,
      # including the legacy plain SVM slugs the x402 v1 wire uses
      # (`solana`, `solana-devnet`, `solana-testnet`) and the friendly
      # cluster names. Mirrors the Rust spine `caip2_network_for_cluster`
      # (rust/crates/x402/src/protocol/schemes/exact/types.rs:31-39) so the
      # v1 network gate compares apples to apples against a CAIP-2 route
      # network. Unknown identifiers fall back to mainnet, matching rust.
      def for_cluster(cluster)
        case cluster.to_s
        when MAINNET, LEGACY_MAINNET, "mainnet", "mainnet-beta"
          MAINNET
        when TESTNET, LEGACY_TESTNET, "testnet"
          TESTNET
        when DEVNET, LEGACY_DEVNET, "devnet", "localnet"
          DEVNET
        else
          MAINNET
        end
      end
    end
  end
end
