# frozen_string_literal: true

require "time"

module Mpp
  # Helpers for RFC3339 expiration timestamps.
  module Expires
    module_function

    # Return an RFC3339 timestamp `minutes` from the supplied clock.
    def minutes(minutes, now: Time.now.utc)
      (now + (minutes * 60)).utc.iso8601
    end
  end
end
