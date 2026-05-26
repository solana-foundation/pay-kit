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
    end
  end
end
