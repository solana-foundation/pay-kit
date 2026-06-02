# frozen_string_literal: true

require "time"

module PayKit::Protocols::Mpp
  # Helpers for RFC3339 expiration timestamps.
  module Expires
    module_function

    # Return an RFC3339 timestamp `minutes` from the supplied clock.
    def minutes(minutes, now: Time.now.utc)
      (now + (minutes * 60)).utc.iso8601
    end

    # Return an RFC3339 timestamp `seconds` from the supplied clock.
    # Used by callers that want sub-minute or arbitrary-second control
    # (e.g. PayKit.config.mpp.expires_in).
    def seconds(seconds, now: Time.now.utc)
      (now + seconds).utc.iso8601
    end
  end
end
