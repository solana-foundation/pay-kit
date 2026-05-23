# frozen_string_literal: true

module Mpp
  # Protocol-level error raised by the Ruby MPP SDK. Carries an optional
  # canonical structured error code (see Mpp::ErrorCodes) so a 402 response
  # body can surface a stable machine-readable identifier on every failure
  # class. `code` is optional; when nil, the response builder classifies the
  # message into a canonical code via Mpp::ErrorCodes.canonical_code.
  class Error < StandardError
    attr_reader :code

    def initialize(message = nil, code: nil)
      super(message)
      @code = code
    end
  end

  # Raised when request or credential fields fail validation.
  class VerificationError < Error; end
end
