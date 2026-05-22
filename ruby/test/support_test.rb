# frozen_string_literal: true

require_relative "test_helper"
require "tmpdir"

class SupportTest < Minitest::Test
  include RubyMppTestHelpers

  def test_memory_store_and_file_store_replay_boundaries
    memory = SolanaMpp::MemoryStore.new
    assert memory.put_if_absent("k", true)
    refute memory.put_if_absent("k", true)

    Dir.mktmpdir do |dir|
      path = File.join(dir, "store.json")
      store = SolanaMpp::FileStore.new(path)
      assert store.put_if_absent("sig", true)
      refute store.put_if_absent("sig", true)
      assert_instance_of SolanaMpp::FileStore, SolanaMpp::FileStore.new(path)
    end
  end

  def test_stablecoin_resolution_and_token_programs
    assert_nil SolanaMpp::Common::StablecoinMints.resolve("SOL", "localnet")
    assert_equal "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", SolanaMpp::Common::StablecoinMints.resolve("USDC", "localnet")
    assert_equal "SomeMint111111111111111111111111111111111", SolanaMpp::Common::StablecoinMints.resolve("SomeMint111111111111111111111111111111111", "localnet")
    assert_equal SolanaMpp::Common::StablecoinMints::TOKEN_2022_PROGRAM, SolanaMpp::Common::StablecoinMints.token_program_for("PYUSD", "devnet")
    assert_equal SolanaMpp::Common::StablecoinMints::TOKEN_PROGRAM, SolanaMpp::Common::StablecoinMints.token_program_for("USDC", "localnet")
    assert_equal "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", SolanaMpp::Common::StablecoinMints.resolve("USDC", "unknown")
    assert_equal "USDC", SolanaMpp::Common::StablecoinMints.symbol_for("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "mainnet-beta")
    assert_nil SolanaMpp::Common::StablecoinMints.symbol_for("unknown", "localnet")
  end

  def test_base58_round_trip_and_invalid_character
    encoded = SolanaMpp::Solana::Base58.encode("\x00\x00abc".b)
    assert_equal "\x00\x00abc".b, SolanaMpp::Solana::Base58.decode(encoded)
    assert_raises(ArgumentError) { SolanaMpp::Solana::Base58.decode("0") }
  end

  def test_keypair_from_json_array_and_errors
    bytes = Array.new(64, 1)
    keypair = SolanaMpp::Solana::Keypair.from_json_array(JSON.generate(bytes))

    assert_equal 64, keypair.sign("hello").bytesize
    assert_equal pubkey(1), keypair.public_key.to_s
    assert_raises(ArgumentError) { SolanaMpp::Solana::Keypair.from_json_array(JSON.generate([1, 2])) }
    assert_raises(ArgumentError) { SolanaMpp::Solana::Keypair.from_json_array(JSON.generate({"bad" => true})) }
  end

  def test_public_key_binary_and_invalid_length_edges
    bytes = "\x01".b * 32
    key = SolanaMpp::Solana::PublicKey.new(bytes)

    assert_equal key, SolanaMpp::Solana::PublicKey.new(key.to_s)
    refute_equal key, Object.new
    assert_raises(ArgumentError) { SolanaMpp::Solana::PublicKey.new("\x01".b * 31) }
  end

  def test_rpc_client_success_and_error_paths
    response = Struct.new(:body)
    calls = []
    with_rpc_http(lambda { |request|
      calls << JSON.parse(request.body)
      response.new(JSON.generate({"result" => {"value" => {"blockhash" => pubkey(9)}}}))
    }) do |clients|
      client = SolanaMpp::Solana::RpcClient.new("http://localhost:8899")
      assert_equal pubkey(9), client.latest_blockhash
      assert_equal 5, clients.first.open_timeout
      assert_equal 10, clients.first.read_timeout
      assert_equal 10, clients.first.write_timeout
    end
    assert_equal "getLatestBlockhash", calls.first.fetch("method")

    with_rpc_http(lambda { |_request| response.new(JSON.generate({"error" => {"message" => "boom"}})) }) do
      error = assert_raises(SolanaMpp::Error) { SolanaMpp::Solana::RpcClient.new("http://localhost:8899").call("bad") }
      assert_match(/boom/, error.message)
    end
  end

  def test_rpc_client_custom_timeouts_and_timeout_errors
    with_rpc_http(lambda { |_request| raise Net::ReadTimeout }) do |clients|
      client = SolanaMpp::Solana::RpcClient.new("https://localhost:8899", open_timeout: 1, read_timeout: 2, write_timeout: 3)
      error = assert_raises(SolanaMpp::Error) { client.call("getLatestBlockhash") }

      assert_match(/timed out/, error.message)
      assert_equal true, clients.first.use_ssl
      assert_equal 1, clients.first.open_timeout
      assert_equal 2, clients.first.read_timeout
      assert_equal 3, clients.first.write_timeout
    end
  end

  def test_rpc_client_wraps_socket_level_network_errors
    with_rpc_http(lambda { |_request| raise Errno::ECONNRESET }) do
      client = SolanaMpp::Solana::RpcClient.new("http://localhost:8899")
      error = assert_raises(SolanaMpp::Error) { client.call("getLatestBlockhash") }

      assert_match(/Solana RPC request failed/, error.message)
      assert_match(/ECONNRESET/, error.message)
    end
  end

  def test_rpc_client_works_without_write_timeout_setter
    response = Struct.new(:body)
    with_rpc_http(lambda { |_request| response.new(JSON.generate({"result" => {"ok" => true}})) }, supports_write_timeout: false) do |clients|
      result = SolanaMpp::Solana::RpcClient.new("http://localhost:8899").call("custom")

      assert_equal({"ok" => true}, result)
      refute clients.first.respond_to?(:write_timeout=)
    end
  end

  def test_rpc_client_method_shapes
    response = Struct.new(:body)
    results = {
      "simulateTransaction" => {"value" => {"err" => nil}},
      "sendTransaction" => "sig",
      "getSignatureStatuses" => {"value" => [{"confirmationStatus" => "confirmed"}]},
      "getTransaction" => {"transaction" => ["tx", "base64"], "meta" => {"err" => nil}}
    }
    with_rpc_http(lambda { |request|
      method = JSON.parse(request.body).fetch("method")
      response.new(JSON.generate({"result" => results.fetch(method)}))
    }) do
      client = SolanaMpp::Solana::RpcClient.new("http://localhost:8899")
      assert_equal({"err" => nil}, client.simulate_transaction("abc"))
      assert_equal "sig", client.send_raw_transaction("abc")
      assert_equal [{"confirmationStatus" => "confirmed"}], client.signature_statuses(["sig"])
      assert_equal({"transaction" => ["tx", "base64"], "meta" => {"err" => nil}}, client.transaction_base64("sig"))
    end
  end

  def with_rpc_http(callable, supports_write_timeout: true)
    original = Net::HTTP.method(:new)
    clients = []
    fake_class = Class.new do
      attr_accessor :use_ssl, :open_timeout, :read_timeout, :write_timeout

      def initialize(callable)
        @callable = callable
      end

      def start
        yield self
      end

      def request(request)
        @callable.call(request)
      end
    end
    fake_class.send(:undef_method, :write_timeout=) unless supports_write_timeout
    Net::HTTP.define_singleton_method(:new) do |_host, _port|
      fake_class.new(callable).tap { |client| clients << client }
    end
    yield clients
  ensure
    Net::HTTP.define_singleton_method(:new) { |host, port| original.call(host, port) }
  end
end
