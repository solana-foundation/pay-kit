# frozen_string_literal: true

require "pay_core/solana/ata"

module Mpp
  module Methods
    module Solana
      # Backward-compat alias. Canonical home: `PayCore::Solana::ATA`.
      # The class name stays `AssociatedToken` here because pre-PayCore
      # MPP code imported it under that name; the underlying module is
      # the same.
      AssociatedToken = ::PayCore::Solana::ATA
    end
  end
end
