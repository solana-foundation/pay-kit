# frozen_string_literal: true

require "time"
require "date"

module PayCore
  # RFC 3339 date-time parser shared by solana-mpp and solana-x402.
  #
  # @see https://datatracker.ietf.org/doc/html/rfc3339 RFC 3339 Date and Time on the Internet
  module Rfc3339Parser
    # Strict RFC 3339 date-time (sec 5.6) without leap-second support
    # at the parse layer. Year is exactly 4 digits; T literal accepted
    # upper or lower (per parse SHOULD); fractional seconds 1..9 digits.
    REGEX = /\A
      (\d{4})-(\d{2})-(\d{2})         # full-date
      [Tt]
      (\d{2}):(\d{2}):(\d{2})         # partial-time
      (?:\.(\d{1,9}))?                # time-secfrac
      (Z|z|[+-]\d{2}:\d{2})           # time-offset
      \z/x
    private_constant :REGEX

    module_function

    # Parse an RFC 3339 timestamp into a Time, or nil when the input is
    # not a valid RFC 3339 date-time. Returns nil for any out-of-range
    # component so callers can fail-closed.
    def parse(value)
      return nil unless value.is_a?(String)

      match = REGEX.match(value)
      return nil unless match

      year, month, day = match[1].to_i, match[2].to_i, match[3].to_i
      hour, minute, second = match[4].to_i, match[5].to_i, match[6].to_i
      return nil if month < 1 || month > 12
      return nil if day < 1 || day > 31
      # RFC 3339 section 5.7 allows seconds = 60 for positive leap seconds;
      # PHP, Lua, and Go SDKs all accept the value at parse-time. Reject only
      # at 61 so a credential timestamped at exactly 23:59:60 UTC parses.
      return nil if hour > 23 || minute > 59 || second > 60
      return nil if year > 9999
      return nil unless Date.valid_date?(year, month, day)

      # Time.iso8601 rejects lowercase 't' / 'z' separators that the regex
      # above accepts (RFC 3339 sec 5.6 allows both cases; ISO 8601 strict
      # requires uppercase). Normalize before delegating so a credential
      # timestamped as ``2099-01-01t00:00:00z`` parses instead of
      # falling into the rescue. PHP already does this; matching here.
      normalized = value
        .sub(/(\d)t(\d)/, "\\1T\\2")
        .sub(/z\z/, "Z")
      Time.iso8601(normalized)
    rescue ArgumentError
      nil
    end
  end
end
