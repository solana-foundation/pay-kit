# frozen_string_literal: true

require_relative "../../../test_helper"

# Regression for: PayKit::Protocols::Mpp.create must loudly warn when no replay_store is
# supplied (the default volatile MemoryStore is dev-only and unsafe in
# production).
class DevStoreWarningTest < Minitest::Test
  include RubyMppTestHelpers

  def method_fixture(network: "localnet")
    PayKit::Protocols::Mpp::Protocol::Solana.charge(
      recipient: pubkey(2),
      currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      network: network,
      rpc: "http://127.0.0.1:8899"
    )
  end

  # When no replay_store is passed on localnet, PayKit::Protocols::Mpp.create must:
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
    assert_match(/outside localnet/i, warned)
  end

  def test_non_localnet_rejects_a_missing_store
    %w[devnet mainnet].each do |network|
      error = assert_raises(PayKit::ConfigurationError) do
        PayKit::Protocols::Mpp.create(
          method: method_fixture(network: network),
          secret_key: ("test-secret-" + ("0" * 32))
        )
      end

      assert_match(/requires a durable replay_store/i, error.message)
      assert_match(/shared across workers/i, error.message)
      assert_match(/#{network}/, error.message)
    end
  end

  def test_non_localnet_rejects_an_explicit_memory_store
    %w[devnet mainnet].each do |network|
      error = assert_raises(PayKit::ConfigurationError) do
        PayKit::Protocols::Mpp.create(
          method: method_fixture(network: network),
          secret_key: ("test-secret-" + ("0" * 32)),
          replay_store: PayKit::Protocols::Mpp::MemoryStore.new
        )
      end

      assert_match(/requires a durable replay_store/i, error.message)
      assert_match(/#{network}/, error.message)
    end
  end

  # When an explicit replay_store is passed on localnet, no
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

  def test_non_localnet_rejects_durable_but_process_local_file_store
    Dir.mktmpdir do |dir|
      file_store = PayKit::Protocols::Mpp::FileStore.new(File.join(dir, "replay.json"))
      refute PayKit::Protocols::Mpp::MemoryStore.new.durable?
      assert file_store.durable?
      refute file_store.shared?

      %w[devnet mainnet].each do |network|
        error = assert_raises(PayKit::ConfigurationError) do
          PayKit::Protocols::Mpp.create(
            method: method_fixture(network: network),
            secret_key: ("test-secret-" + ("0" * 32)),
            replay_store: file_store
          )
        end
        assert_match(/shared across workers/i, error.message)
      end
    end
  end

  def test_non_localnet_accepts_an_explicit_durable_shared_store
    store = DurableSharedStore.new

    %w[devnet mainnet].each do |network|
      server = PayKit::Protocols::Mpp.create(
        method: method_fixture(network: network),
        secret_key: ("test-secret-" + ("0" * 32)),
        replay_store: store
      )
      assert_kind_of PayKit::Protocols::Mpp::Server::Charge, server
    end
  end

  class DurableSharedStore < PayKit::Protocols::Mpp::Store
    def durable?
      true
    end

    def shared?
      true
    end

    def put_if_absent(_key, _value)
      true
    end
  end
end
