# frozen_string_literal: true

require "pay_core/solana/account"

module PayKit
  module Signer
    # Local in-process signer backed by a 64-byte Solana Ed25519 keypair.
    # Wraps `PayCore::Solana::Account` so PayKit avoids re-implementing the
    # cryptographic primitives that already live in the shared core layer.
    # The public duck-type contract (`#pubkey`, `#sign(message)`,
    # `#fee_payer?`, `#demo?`) is what every PayKit code path consumes;
    # future remote signers under `PayKit::Kms` will satisfy the same
    # contract with async semantics.
    class Local
      attr_reader :secret_bytes

      def initialize(bytes_64)
        unless bytes_64.is_a?(Array) && bytes_64.length == 64 && bytes_64.all? { |b| b.is_a?(Integer) && (0..255).cover?(b) }
          raise ::PayKit::Signer::InvalidKeyError,
            "secret must be a 64-element Array of byte integers, got #{bytes_64.class.name}"
        end

        @secret_bytes = bytes_64.dup.freeze
        @account = ::PayCore::Solana::Account.new(@secret_bytes)
        freeze
      end

      # Base58-encoded Solana public key (44 chars).
      def pubkey
        @account.public_key.to_s
      end

      # Sign raw message bytes; returns a 64-byte Ed25519 signature String.
      def sign(message)
        @account.sign(message)
      end

      # Whether this signer should be used as the Solana fee payer on
      # settlement transactions. `true` for local signers; remote/KMS
      # signers may flip this if they need to opt out of fee payment.
      def fee_payer?
        true
      end

      # Subclasses (`Signer::Demo`) override this to `true`. Used by
      # `PayKit::Config` to enforce the mainnet refusal rule.
      def demo?
        false
      end

      # JSON-array string form (Solana CLI keypair format), useful for
      # passing the underlying secret through legacy x402/MPP server
      # constructors that still want a JSON-array literal during the
      # transition. Internal use only.
      def to_json_array
        JSON.generate(@secret_bytes)
      end

      # The underlying PayCore::Solana::Account used for low-level chain
      # primitives (signing transactions, computing the fee-payer
      # pubkey for MPP method_details). Exposed only for PayKit's own
      # protocol adapters; ordinary app code consumes the duck-typed
      # signer interface (#pubkey, #sign, #fee_payer?).
      def to_pay_core_account
        @account
      end
    end
  end
end
