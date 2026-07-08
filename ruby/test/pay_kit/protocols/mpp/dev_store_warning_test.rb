# frozen_string_literal: true

require_relative "../../../test_helper"

# Regression for: PayKit::Protocols::Mpp.create must loudly warn when no replay_store is
# supplied (the default volatile MemoryStore is dev-only and unsafe in
# production).
class DevStoreWarningTest < Minitest::Test
  include RubyMppTestHelpers

  def method_fixture
    PayKit::Protocols::Mpp::Protocol::Solana.charge(
      recipient: pubkey(2),
      currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      network: "localnet",
      rpc: "http://127.0.0.1:8899"
    )
  end

  # When no replay_store is passed, PayKit::Protocols::Mpp.create must:
  #   (a) emit a warning to stderr that includes "MemoryStore" and "no replay_store"
  #   (b) still return a working PayKit::Protocols::Mpp::Server::Charge instance
  def test_no_store_argument_emits_dev_warning
    warned = nil

    # Capture the Kernel.warn output without actually printing it.
    PayKit::Protocols::Mpp.stub(:warn, ->(msg) { warned = msg }) do
      server = PayKit::Protocols::Mpp.create(method: method_fixture, secret_key: ("test-secret-" + ("0" * 32)))
      assert_kind_of PayKit::Protocols::Mpp::Server::Charge, server
    end

    refute_nil warned, "expected a warning to be emitted"
    assert_match(/no replay_store/i, warned)
    assert_match(/MemoryStore/i, warned)
    assert_match(/production/i, warned)
  end

  # When an explicit replay_store is passed (even a MemoryStore), no
  # warning must be emitted. This ensures the warning is opt-in — callers
  # that knowingly use MemoryStore in tests can pass PayKit::Protocols::Mpp::MemoryStore.new
  # explicitly and stay warning-free.
  def test_explicit_store_argument_suppresses_warning
    warned = []
    explicit_store = PayKit::Protocols::Mpp::MemoryStore.new

    PayKit::Protocols::Mpp.stub(:warn, ->(msg) { warned << msg }) do
      server = PayKit::Protocols::Mpp.create(
        method: method_fixture,
        secret_key: ("test-secret-" + ("0" * 32)),
        replay_store: explicit_store
      )
      assert_kind_of PayKit::Protocols::Mpp::Server::Charge, server
    end

    assert_empty warned, "expected no warning when an explicit store is provided"
  end

  # When an explicit FileStore is passed, no warning must be emitted.
  def test_explicit_file_store_suppresses_warning
    warned = []
    Dir.mktmpdir do |dir|
      file_store = PayKit::Protocols::Mpp::FileStore.new(File.join(dir, "replay.json"))

      PayKit::Protocols::Mpp.stub(:warn, ->(msg) { warned << msg }) do
        server = PayKit::Protocols::Mpp.create(
          method: method_fixture,
          secret_key: ("test-secret-" + ("0" * 32)),
          replay_store: file_store
        )
        assert_kind_of PayKit::Protocols::Mpp::Server::Charge, server
      end
    end

    assert_empty warned, "expected no warning when FileStore is provided"
  end
end
