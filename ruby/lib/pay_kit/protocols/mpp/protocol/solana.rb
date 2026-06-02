# frozen_string_literal: true

require "pay_core/solana/rpc"
require "pay_core/solana/mints"

module PayKit::Protocols::Mpp
  module Protocol
    module Solana
      # Build a Solana charge method bundling all static config (recipient,
      # currency, network, RPC, optional fee payer, decimals). Pass the result
      # to PayKit::Protocols::Mpp.create(method:, ...).
      #
      # `currency` accepts a symbol like "USDC" or "SOL" (looked up against
      # the built-in stablecoin table) or a raw 32-byte mint address.
      #
      #   method = PayKit::Protocols::Mpp::Protocol::Solana.charge(
      #     recipient: "CXhr...",
      #     currency:  "USDC",
      #     network:   "mainnet",
      #     rpc:       "https://api.mainnet-beta.solana.com",
      #   )
      def self.charge(recipient:, currency:, rpc:, network: "mainnet", fee_payer: nil, decimals: nil)
        ChargeMethod.new(
          recipient: recipient,
          currency: currency,
          network: network,
          rpc: rpc.is_a?(String) ? ::PayCore::Solana::Rpc.new(rpc) : rpc,
          fee_payer: fee_payer,
          decimals: decimals || ::PayCore::Solana::Mints.decimals_for(currency, network)
        )
      end

      # Per-rail config for a Solana charge endpoint. Owns the RPC client,
      # verifier, network identity, and (optionally) a server-side fee payer.
      class ChargeMethod
        BLOCKHASH_TTL_SECONDS = 2.0

        attr_reader :recipient, :currency, :network, :rpc, :fee_payer, :decimals, :verifier

        def initialize(recipient:, currency:, network:, rpc:, fee_payer:, decimals:)
          @recipient = recipient
          @currency = currency
          @network = network
          @rpc = rpc
          @fee_payer = fee_payer
          @decimals = decimals
          @verifier = Verifier.new
          @blockhash = nil
          @blockhash_at = 0.0
        end

        # Public key of the server-side fee payer, or nil when not configured.
        def fee_payer_pubkey
          fee_payer&.public_key&.to_s
        end

        # Default SPL token program for this method's currency+network pair.
        def token_program
          ::PayCore::Solana::Mints.token_program_for(currency, network)
        end

        # Short-window blockhash cache: every protected request would otherwise
        # spend an RPC round-trip just to get a fresh blockhash. 2s amortizes
        # this without risk to challenge validity (Solana keeps blockhashes
        # valid for ~60s).
        def latest_blockhash
          now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          return @blockhash if @blockhash && (now - @blockhash_at) < BLOCKHASH_TTL_SECONDS

          @blockhash = rpc.latest_blockhash
          @blockhash_at = now
          @blockhash
        end

        # Build the wire-level method_details hash for a charge request.
        # Pass `currency:` to override the method's default — useful when one
        # endpoint accepts multiple currencies (USDC, USDT, ...) and selects
        # one per request.
        def method_details(currency: self.currency)
          details = {
            "network" => network,
            "decimals" => (currency == self.currency) ? decimals : ::PayCore::Solana::Mints.decimals_for(currency, network),
            "tokenProgram" => ::PayCore::Solana::Mints.token_program_for(currency, network),
            "recentBlockhash" => latest_blockhash
          }
          if fee_payer
            details["feePayer"] = true
            details["feePayerKey"] = fee_payer_pubkey
          end
          details
        end
      end
    end
  end
end
