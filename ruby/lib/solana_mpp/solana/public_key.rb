# frozen_string_literal: true

require "digest"

module SolanaMpp
  module Solana
    # Base58 Solana public key wrapper.
    class PublicKey
      PROGRAM_DERIVED_ADDRESS_SEED = "ProgramDerivedAddress"
      P = (2**255) - 19
      D = (-121665 * 121666.pow(P - 2, P)) % P

      attr_reader :bytes

      def initialize(value)
        @bytes = if value.is_a?(String) && value.encoding == Encoding::BINARY && value.bytesize == 32
          value.bytes
        elsif value.is_a?(String)
          Base58.decode(value).bytes
        else
          value.bytes
        end
        raise ArgumentError, "public key must be 32 bytes" unless @bytes.length == 32
      end

      # Return the Base58 representation.
      def to_s
        Base58.encode(bytes.pack("C*"))
      end

      # Compare public-key bytes.
      def ==(other)
        other.is_a?(PublicKey) && bytes == other.bytes
      end

      # Derive a Solana program address.
      def self.find_program_address(seeds, program_id)
        program = PublicKey.new(program_id).bytes.pack("C*")
        255.downto(0) do |bump|
          candidate = Digest::SHA256.digest(seeds.join + [bump].pack("C") + program + PROGRAM_DERIVED_ADDRESS_SEED)
          return [PublicKey.new(candidate), bump] unless on_curve?(candidate)
        end
        raise ArgumentError, "unable to find program address"
      end

      def self.on_curve?(encoded)
        bytes = encoded.bytes
        y = bytes.each_with_index.reduce(0) { |memo, (byte, index)| memo + (byte << (8 * index)) }
        y &= (1 << 255) - 1
        y2 = mod(y * y)
        u = mod(y2 - 1)
        v = mod((D * y2) + 1)
        x2 = mod(u * inv(v))
        sqrt = sqrt_ratio(x2)
        !sqrt.nil?
      end

      def self.mod(value)
        value % P
      end

      def self.inv(value)
        value.pow(P - 2, P)
      end

      def self.sqrt_ratio(value)
        root = value.pow((P + 3) / 8, P)
        root = mod(root * 2.pow((P - 1) / 4, P)) if mod(root * root - value) != 0
        return nil unless mod(root * root - value) == 0

        root
      end
    end
  end
end
