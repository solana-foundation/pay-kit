# frozen_string_literal: true

require_relative "public_key"
require_relative "mints"

module PayCore
  module Solana
    # Associated Token Account derivation helper. Mirrors the Rust spine
    # `rust/crates/core/src/solana/ata.rs`.
    module ATA
      module_function

      # Derive the ATA address for the given owner / mint / token-program.
      def derive(owner:, mint:, token_program:)
        PublicKey.find_program_address(
          [
            PublicKey.new(owner).bytes.pack("C*"),
            PublicKey.new(token_program).bytes.pack("C*"),
            PublicKey.new(mint).bytes.pack("C*")
          ],
          Mints::ASSOCIATED_TOKEN_PROGRAM
        ).first.to_s
      end
    end
  end
end
