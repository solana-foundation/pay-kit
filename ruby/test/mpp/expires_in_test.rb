# frozen_string_literal: true

require_relative "../test_helper"
require "time"

class MppExpiresInTest < Minitest::Test
  def test_expires_seconds_returns_rfc3339_at_offset
    now = Time.utc(2026, 1, 1, 12, 0, 0)
    result = ::Mpp::Expires.seconds(42, now: now)
    parsed = Time.iso8601(result)
    assert_equal Time.utc(2026, 1, 1, 12, 0, 42), parsed.utc
  end

  def test_challenge_store_default_expires_seconds
    store = ::Mpp::Protocol::Core::ChallengeStore.new(secret_key: "secret", realm: "Test")
    assert_equal 300, store.default_expires_seconds
  end

  def test_challenge_store_honors_custom_default_expires_seconds
    store = ::Mpp::Protocol::Core::ChallengeStore.new(
      secret_key: "secret", realm: "Test", default_expires_seconds: 60
    )
    assert_equal 60, store.default_expires_seconds
  end

  def test_challenge_store_create_challenge_uses_default_expiry
    store = ::Mpp::Protocol::Core::ChallengeStore.new(
      secret_key: "secret", realm: "Test", default_expires_seconds: 90
    )
    request = ::Mpp::Protocol::Intents::ChargeRequest.new(
      amount: "100", currency: "USDC",
      recipient: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj",
      method_details: {"network" => "devnet"}
    )
    before = Time.now.utc
    challenge = store.create_challenge(request)
    after = Time.now.utc

    parsed = Time.iso8601(challenge.expires)
    assert parsed >= before + 89, "expiry should be ~90s in the future, got #{parsed - before}"
    assert parsed <= after + 91
  end

  def test_mpp_create_threads_expires_in
    method = ::Mpp::Protocol::Solana.charge(
      recipient: "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj",
      currency: "USDC",
      network: "devnet",
      rpc: "https://api.devnet.solana.com"
    )
    server = ::Mpp.create(method: method, secret_key: "secret", realm: "Test", expires_in: 42)
    store = server.instance_variable_get(:@challenge_store)
    assert_equal 42, store.default_expires_seconds
  end
end
