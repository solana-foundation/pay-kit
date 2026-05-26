# frozen_string_literal: true

# RFC 3339 expires parser test cases for the Ruby SDK. Isolated from
# core_test.rb per PR #102 review (inline comment 3298060956) so RFC 8785
# (canonical JSON) and RFC 3339 (expires) live in dedicated files.
# Battle-tested vector imports are tracked separately (see follow-up
# issue referenced on the same PR thread).
require_relative "test_helper"

class ExpiresRfc3339Test < Minitest::Test
  include RubyMppTestHelpers

  def test_expires_strict_rfc3339
    chal = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:00:00Z")
    refute chal.expired?
    chal2 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "tomorrow")
    assert chal2.expired?, "non-RFC-3339 expires must fail closed"
    chal3 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "10000-01-01T00:00:00Z")
    assert chal3.expired?, "5-digit year must fail closed"
  end

  def test_expires_strict_rfc3339_extra
    # Month 13 rejected.
    c = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-13-01T00:00:00Z")
    assert c.expired?
    # Minute 60 rejected.
    c2 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:60:00Z")
    assert c2.expired?
    # Day 0 rejected.
    c3 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-00T00:00:00Z")
    assert c3.expired?
  end

  # Rfc3339Parser parser-error branches (cover the explicit nil-returning
  # arms so SimpleCov branch coverage stays >= 90 cross-SDK baseline).
  def test_rfc3339_parser_explicit_error_branches
    parser = ::PayCore::Rfc3339Parser
    assert_nil parser.parse(123) # non-string input
    assert_nil parser.parse("not-a-timestamp")
    assert_nil parser.parse("2099-13-01T00:00:00Z") # month > 12
    assert_nil parser.parse("2099-00-01T00:00:00Z") # month < 1
    assert_nil parser.parse("2099-01-00T00:00:00Z") # day < 1
    assert_nil parser.parse("2099-01-32T00:00:00Z") # day > 31
    assert_nil parser.parse("2099-01-01T24:00:00Z") # hour > 23
    assert_nil parser.parse("2099-01-01T00:60:00Z") # minute > 59
    assert_nil parser.parse("2099-01-01T00:00:61Z") # second > 60
    assert_nil parser.parse("10000-01-01T00:00:00Z") # year > 9999
    assert_nil parser.parse("2099-02-30T00:00:00Z") # invalid calendar date
    assert_nil parser.parse("2099-01-01T00:00:00+99:00") # invalid offset hour
  end

  def test_rfc3339_parser_accepts_valid_variants
    parser = ::PayCore::Rfc3339Parser
    refute_nil parser.parse("2099-01-01t00:00:00z") # lowercase t/z
    refute_nil parser.parse("2099-01-01T00:00:00.123456789Z") # 9 fractional digits
    refute_nil parser.parse("2099-12-31T23:59:60Z") # leap second
    refute_nil parser.parse("2099-01-01T00:00:00-08:00") # negative offset
  end

  def test_expires_strict_rfc3339_branches
    # Lowercase t accepted.
    c1 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01t00:00:00Z")
    refute c1.expired?
    # Fractional seconds accepted.
    c2 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:00:00.123Z")
    refute c2.expired?
    # Numeric offset accepted.
    c3 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:00:00+00:00")
    refute c3.expired?
    # Invalid calendar date rejected (Feb 30).
    c4 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-02-30T00:00:00Z")
    assert c4.expired?
    # Hour 24 rejected.
    c5 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T24:00:00Z")
    assert c5.expired?
    # RFC 3339 section 5.7: positive leap-second seconds=60 must be accepted
    # (PHP, Lua, Go SDKs accept it; Ruby previously rejected with second > 59).
    c6 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-12-31T23:59:60Z")
    refute c6.expired?
    # seconds = 61 stays rejected.
    c7 = Mpp::Protocol::Core::Challenge.with_secret(secret_key: "s", realm: "api", method: "solana", intent: "charge", request: {}, expires: "2099-01-01T00:00:61Z")
    assert c7.expired?
  end
end
