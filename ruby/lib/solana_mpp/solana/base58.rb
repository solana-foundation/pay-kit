# frozen_string_literal: true

module SolanaMpp
  module Solana
    # Bitcoin-alphabet Base58 helpers used by Solana public keys/signatures.
    module Base58
      ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

      module_function

      # Encode binary bytes as a Base58 string.
      def encode(binary)
        int = binary.bytes.reduce(0) { |memo, byte| (memo << 8) + byte }
        encoded = +""
        while int.positive?
          int, mod = int.divmod(58)
          encoded << ALPHABET[mod]
        end
        leading = binary.bytes.take_while(&:zero?).length
        ("1" * leading) + encoded.reverse
      end

      # Decode a Base58 string into binary bytes.
      def decode(value)
        int = 0
        value.each_char do |char|
          index = ALPHABET.index(char)
          raise ArgumentError, "Value passed not a valid Base58 String." if index.nil?

          int = (int * 58) + index
        end
        bytes = []
        while int.positive?
          bytes.unshift(int & 0xff)
          int >>= 8
        end
        ("\x00".b * value.each_char.take_while { |char| char == "1" }.length) + bytes.pack("C*")
      end
    end
  end
end
