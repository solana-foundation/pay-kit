# frozen_string_literal: true

module SolanaMpp
  # Protocol-level error raised by the Ruby MPP SDK.
  class Error < StandardError; end

  # Raised when request or credential fields fail validation.
  class VerificationError < Error; end
end
