# frozen_string_literal: true

require "base64"

module PayCore
  # Base64url helpers for Payment header JSON fields. Shared by solana-mpp
  # and solana-x402; mirrors the Rust spine
  # `rust/crates/core/src/base64_url.rs`.
  module Base64Url
    module_function

    # Encode bytes with URL-safe alphabet and no padding.
    def encode(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end

    # Decode URL-safe or standard Base64 input.
    def decode(value)
      Base64.urlsafe_decode64(value)
    rescue ArgumentError
      Base64.decode64(value)
    end
  end
end
