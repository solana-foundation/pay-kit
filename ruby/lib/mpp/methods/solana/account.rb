# frozen_string_literal: true

require "pay_core/solana/account"

module Mpp
  module Methods
    module Solana
      # Backward-compat alias. Canonical home: `PayCore::Solana::Account`.
      Account = ::PayCore::Solana::Account
    end
  end
end
