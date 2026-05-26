# frozen_string_literal: true

require "pay_core/solana/public_key"

module Mpp
  module Methods
    module Solana
      # Backward-compat alias. Canonical home: `PayCore::Solana::PublicKey`.
      PublicKey = ::PayCore::Solana::PublicKey
    end
  end
end
