# frozen_string_literal: true

require "pay_core/solana/mints"

module Mpp
  module Methods
    module Solana
      # Backward-compat alias. Canonical home: `PayCore::Solana::Mints`.
      Mints = ::PayCore::Solana::Mints
    end
  end
end
