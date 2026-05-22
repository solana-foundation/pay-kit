# frozen_string_literal: true

module Mpp
  module Methods
    module Solana
      # Build a Solana charge method bundling all static config (recipient,
      # mint, network, RPC, optional fee payer, decimals). Pass the result
      # to Mpp.create(method:, ...).
      #
      #   method = Mpp::Methods::Solana.charge(
      #     recipient: "CXhr...",
      #     mint:      "USDC",
      #     network:   "mainnet-beta",
      #     rpc:       "https://api.mainnet-beta.solana.com",
      #   )
      def self.charge(recipient:, mint:, rpc:, network: "mainnet-beta", fee_payer: nil, decimals: 6)
        ChargeMethod.new(
          recipient: recipient,
          mint:      mint,
          network:   network,
          rpc:       rpc.is_a?(String) ? Rpc.new(rpc) : rpc,
          fee_payer: fee_payer,
          decimals:  decimals
        )
      end

      # Per-rail config for a Solana charge endpoint. Owns the RPC client,
      # verifier, network identity, and (optionally) a server-side fee payer.
      class ChargeMethod
        BLOCKHASH_TTL_SECONDS = 2.0

        attr_reader :recipient, :mint, :network, :rpc, :fee_payer, :decimals, :verifier

        def initialize(recipient:, mint:, network:, rpc:, fee_payer:, decimals:)
          @recipient = recipient
          @mint      = mint
          @network   = network
          @rpc       = rpc
          @fee_payer = fee_payer
          @decimals  = decimals
          @verifier  = Verifier.new
          @blockhash = nil
          @blockhash_at = 0.0
        end

        # Public key of the server-side fee payer, or nil when not configured.
        def fee_payer_pubkey
          fee_payer&.public_key&.to_s
        end

        # Default SPL token program for this method's mint+network pair.
        def token_program
          Mints.token_program_for(mint, network)
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
        def method_details
          details = {
            "network"         => network,
            "decimals"        => decimals,
            "tokenProgram"    => token_program,
            "recentBlockhash" => latest_blockhash
          }
          if fee_payer
            details["feePayer"]    = true
            details["feePayerKey"] = fee_payer_pubkey
          end
          details
        end
      end
    end
  end
end
