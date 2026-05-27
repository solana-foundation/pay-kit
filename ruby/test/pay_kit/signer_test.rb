# frozen_string_literal: true

require_relative "test_helper"
require "tempfile"

class PayKitSignerTest < Minitest::Test
  # 64-byte test keypair distinct from the published demo so tests cover
  # the non-demo factory paths too.
  RAW_BYTES = (1..64).to_a.freeze
  RAW_PUBKEY_LOCAL = PayCore::Solana::Account.new(RAW_BYTES.dup).public_key.to_s

  def setup
    @held_env = ENV.to_h.select { |key, _| key.start_with?("PAY_KIT_TEST_SIGNER_") }
  end

  def teardown
    ENV.delete_if { |key, _| key.start_with?("PAY_KIT_TEST_SIGNER_") }
    @held_env.each { |key, value| ENV[key] = value }
  end

  # --- contract --------------------------------------------------------

  def test_each_factory_returns_a_local_signer_satisfying_duck_type
    factories = {
      bytes: PayKit::Signer.bytes(RAW_BYTES.dup),
      json: PayKit::Signer.json(JSON.generate(RAW_BYTES)),
      base58: PayKit::Signer.base58(PayCore::Solana::Base58.encode(RAW_BYTES.pack("C*"))),
      hex: PayKit::Signer.hex(RAW_BYTES.pack("C*").unpack1("H*"))
    }

    factories.each do |label, signer|
      assert_kind_of PayKit::Signer::Local, signer, "#{label} should return a Local"
      assert_equal RAW_PUBKEY_LOCAL, signer.pubkey, "#{label} pubkey mismatch"
      assert_equal 64, signer.sign("hello").bytesize, "#{label} signature length"
      assert signer.fee_payer?, "#{label} fee_payer?"
      refute signer.demo?, "#{label} should not report demo?"
    end
  end

  def test_signer_is_frozen
    signer = PayKit::Signer.bytes(RAW_BYTES.dup)
    assert signer.frozen?
    assert signer.secret_bytes.frozen?
  end

  # --- demo ------------------------------------------------------------

  def test_demo_returns_stable_pubkey_and_demo_predicate
    demo = PayKit::Signer.demo
    assert_equal PayKit::Signer::Demo::PUBKEY, demo.pubkey
    assert demo.demo?
    assert demo.fee_payer?
    assert_equal 64, demo.sign("x").bytesize
  end

  def test_demo_instance_is_cached
    a = PayKit::Signer.demo
    b = PayKit::Signer.demo
    assert_same a, b
  end

  def test_demo_emits_boot_warning_once
    PayKit::Signer::Demo.send(:reset!)
    captured = capture_logger
    PayKit.logger = captured

    PayKit::Signer.demo
    PayKit::Signer.demo
    PayKit::Signer.demo

    assert_equal 1, captured.warnings.length, "warning must fire only on first instantiation"
    assert_match(/MUST NOT be used in production/, captured.warnings.first)
  ensure
    PayKit.logger = nil
    PayKit::Signer::Demo.send(:reset!)
  end

  def test_demo_bytes_round_trip_via_bytes_factory
    via_factory = PayKit::Signer.bytes(PayKit::Signer::Demo::SECRET_BYTES.dup)
    assert_equal PayKit::Signer.demo.pubkey, via_factory.pubkey
    refute via_factory.demo?, "Signer.bytes(demo_secret) should not report demo? — only Signer.demo does"
  end

  # --- bytes -----------------------------------------------------------

  def test_bytes_rejects_wrong_length
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.bytes([1, 2, 3]) }
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.bytes(Array.new(63, 0)) }
  end

  def test_bytes_rejects_non_array
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.bytes("not an array") }
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.bytes(nil) }
  end

  def test_bytes_rejects_out_of_range_byte
    bytes = RAW_BYTES.dup
    bytes[0] = 300
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.bytes(bytes) }
  end

  # --- json ------------------------------------------------------------

  def test_json_rejects_non_array_root
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.json('{"not": "array"}') }
  end

  def test_json_rejects_malformed
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.json("not json at all") }
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.json("[1, 2,") }
  end

  # --- base58 ----------------------------------------------------------

  def test_base58_rejects_malformed
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.base58("0OIl") }
  end

  # --- hex -------------------------------------------------------------

  def test_hex_rejects_odd_length
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.hex("abc") }
  end

  def test_hex_rejects_non_hex_chars
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.hex("zz" * 64) }
  end

  # --- file ------------------------------------------------------------

  def test_file_reads_json_array
    Tempfile.create(["paykit_signer_test", ".json"]) do |file|
      file.write(JSON.generate(RAW_BYTES))
      file.flush

      signer = PayKit::Signer.file(file.path)
      assert_equal RAW_PUBKEY_LOCAL, signer.pubkey
    end
  end

  def test_file_raises_on_missing_path
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.file("/no/such/path/keypair.json") }
  end

  # --- env -------------------------------------------------------------

  def test_env_returns_nil_when_unset
    ENV.delete("PAY_KIT_TEST_SIGNER_UNSET")
    assert_nil PayKit::Signer.env("PAY_KIT_TEST_SIGNER_UNSET")
  end

  def test_env_returns_nil_when_empty
    ENV["PAY_KIT_TEST_SIGNER_EMPTY"] = ""
    assert_nil PayKit::Signer.env("PAY_KIT_TEST_SIGNER_EMPTY")
  end

  def test_env_detects_json_array
    ENV["PAY_KIT_TEST_SIGNER_JSON"] = JSON.generate(RAW_BYTES)
    signer = PayKit::Signer.env("PAY_KIT_TEST_SIGNER_JSON")
    assert_equal RAW_PUBKEY_LOCAL, signer.pubkey
  end

  def test_env_detects_hex
    ENV["PAY_KIT_TEST_SIGNER_HEX"] = RAW_BYTES.pack("C*").unpack1("H*")
    signer = PayKit::Signer.env("PAY_KIT_TEST_SIGNER_HEX")
    assert_equal RAW_PUBKEY_LOCAL, signer.pubkey
  end

  def test_env_detects_base58
    ENV["PAY_KIT_TEST_SIGNER_B58"] = PayCore::Solana::Base58.encode(RAW_BYTES.pack("C*"))
    signer = PayKit::Signer.env("PAY_KIT_TEST_SIGNER_B58")
    assert_equal RAW_PUBKEY_LOCAL, signer.pubkey
  end

  def test_env_raises_on_malformed
    ENV["PAY_KIT_TEST_SIGNER_BAD"] = "0OIl this is not a valid key"
    assert_raises(PayKit::Signer::InvalidKeyError) { PayKit::Signer.env("PAY_KIT_TEST_SIGNER_BAD") }
  end

  def test_env_strips_whitespace
    ENV["PAY_KIT_TEST_SIGNER_WS"] = "  #{JSON.generate(RAW_BYTES)}  "
    signer = PayKit::Signer.env("PAY_KIT_TEST_SIGNER_WS")
    assert_equal RAW_PUBKEY_LOCAL, signer.pubkey
  end

  # --- generate --------------------------------------------------------

  def test_generate_returns_fresh_keypair_each_call
    a = PayKit::Signer.generate
    b = PayKit::Signer.generate
    refute_equal a.pubkey, b.pubkey, "generate must produce distinct keypairs"
    assert_kind_of PayKit::Signer::Local, a
  end

  # --- error classes ---------------------------------------------------

  def test_invalid_key_error_is_a_pay_kit_error
    assert_operator PayKit::Signer::InvalidKeyError, :<, PayKit::Error
  end

  def test_demo_signer_on_mainnet_error_is_configuration_error
    assert_operator PayKit::DemoSignerOnMainnetError, :<, PayKit::ConfigurationError
    error = PayKit::DemoSignerOnMainnetError.new("PUBKEY123")
    assert_match(/PUBKEY123/, error.message)
    assert_match(/:solana_mainnet/, error.message)
  end

  private

  # Minimal stand-in for `::Logger`. Captures warn/info/debug calls for
  # assertion.
  def capture_logger
    Class.new do
      attr_reader :warnings, :infos

      def initialize
        @warnings = []
        @infos = []
      end

      def warn(msg = nil)
        msg = yield if block_given?
        @warnings << msg
      end

      def info(msg = nil)
        msg = yield if block_given?
        @infos << msg
      end

      def debug(*)
      end

      def error(*)
      end
    end.new
  end
end
