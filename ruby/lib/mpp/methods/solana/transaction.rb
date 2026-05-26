# frozen_string_literal: true

require "pay_core/solana/transaction"
require_relative "../../error"

module Mpp
  module Methods
    module Solana
      # MPP-flavoured Solana transaction wrapper. Inherits the canonical
      # wire codec from `PayCore::Solana::Transaction`; only the
      # `sign_with` error class is overridden so existing MPP callers
      # rescuing `Mpp::VerificationError` keep working unchanged.
      class Transaction < ::PayCore::Solana::Transaction
        # `PayCore::Solana::Transaction.from_bytes` constructs `new(...)`
        # so subclassing preserves identity. The `Message`, `Instruction`,
        # `AddressLookup`, and `Cursor` classes are exposed under the
        # MPP namespace as plain aliases to avoid double allocation.

        private

        def signing_error_class
          ::Mpp::VerificationError
        end
      end

      # Backward-compat aliases so `Mpp::Methods::Solana::Message`,
      # `Instruction`, `AddressLookup`, and `Cursor` continue to resolve.
      Message = ::PayCore::Solana::Message
      Instruction = ::PayCore::Solana::Instruction
      AddressLookup = ::PayCore::Solana::AddressLookup
      Cursor = ::PayCore::Solana::Cursor
    end
  end
end
