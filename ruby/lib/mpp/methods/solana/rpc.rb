# frozen_string_literal: true

require "pay_core/solana/rpc"
require_relative "../../error"

module Mpp
  module Methods
    module Solana
      # MPP-flavoured Solana RPC client: same wire behaviour as
      # `PayCore::Solana::Rpc`, but raises the canonical `Mpp::Error` (a
      # `StandardError` subclass tagged with an optional L6 code) instead
      # of the generic `PayCore::Solana::Rpc::RpcError`. Backward-compat
      # alias for pre-PayCore callers.
      class Rpc < ::PayCore::Solana::Rpc
        private

        def rpc_error_class
          ::Mpp::Error
        end
      end
    end
  end
end
