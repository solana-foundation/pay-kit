# frozen_string_literal: true

module Mpp
  module Methods
    module Solana
      # Associated token account derivation helper.
      module AssociatedToken
        module_function

        # Derive the ATA for owner/mint/token-program.
        def derive(owner:, mint:, token_program:)
          Solana::PublicKey.find_program_address(
            [
              Solana::PublicKey.new(owner).bytes.pack("C*"),
              Solana::PublicKey.new(token_program).bytes.pack("C*"),
              Solana::PublicKey.new(mint).bytes.pack("C*")
            ],
            Mints::ASSOCIATED_TOKEN_PROGRAM
          ).first.to_s
        end
      end
    end
  end
end
