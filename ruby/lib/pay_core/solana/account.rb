# frozen_string_literal: true

require "ed25519"
require "json"

require_relative "public_key"

module PayCore
  module Solana
    # In-memory Solana Ed25519 account loaded from canonical JSON bytes.
    # Backed by the `ed25519` runtime gem; mirrors the Rust spine signer
    # interface (sign raw message bytes, no pre-hashing).
    class Account
      attr_reader :secret_key, :public_key

      def initialize(bytes)
        raise ArgumentError, "account must have 64 bytes" unless bytes.length == 64

        @secret_key = bytes
        @signing_key = ::Ed25519::SigningKey.new(bytes[0, 32].pack("C*"))
        @public_key = PublicKey.new(bytes[32, 32].pack("C*"))
      end

      # Build an account from a JSON array string of 64 bytes.
      def self.from_json_array(raw)
        bytes = JSON.parse(raw)
        raise ArgumentError, "secret key must be a JSON array" unless bytes.is_a?(Array)

        new(bytes.map { |byte| Integer(byte) })
      end

      # Sign Solana message bytes.
      def sign(message)
        @signing_key.sign(message)
      end
    end
  end
end
