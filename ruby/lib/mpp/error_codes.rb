# frozen_string_literal: true

require "pay_core/error_codes"

module Mpp
  # Backward-compat alias. Canonical home: `PayCore::ErrorCodes`. The
  # canonical L6 codes plus the legacy-to-canonical mapping and the
  # message-pattern classifier live in PayCore so solana-mpp and
  # solana-x402 share one source of truth.
  ErrorCodes = ::PayCore::ErrorCodes
end
