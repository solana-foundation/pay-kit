# frozen_string_literal: true

require "pay_core/solana/base58"

module Mpp
  module Methods
    module Solana
      # Backward-compat alias. The canonical home is
      # `PayCore::Solana::Base58`; existing MPP callers that import this
      # constant keep working unchanged.
      Base58 = ::PayCore::Solana::Base58
    end
  end
end
