# frozen_string_literal: true

require_relative "test_helper"

class PayKitConfigTest < Minitest::Test
  def setup
    PayKit.reset!
    @captured_logs = []
    PayKit.logger = capture_logger(@captured_logs)
    PayKit::Config.reset_deprecation_memo!
  end

  def teardown
    PayKit.reset!
    PayKit.logger = nil
    PayKit::Signer::Demo.send(:reset!)
  end

  # --- defaults --------------------------------------------------------

  def test_default_network_is_localnet
    PayKit.configure { |_c| }
    assert_equal :solana_localnet, PayKit.config.network
  end

  def test_default_accept_and_stablecoins
    PayKit.configure { |_c| }
    assert_equal %i[x402 mpp], PayKit.config.accept
    assert_equal %i[USDC], PayKit.config.stablecoins
  end

  def test_default_operator_is_demo_signer_with_fee_payer_true
    PayKit.configure { |_c| }
    assert PayKit.config.operator.signer.demo?
    assert PayKit.config.operator.fee_payer?
    assert_equal PayKit::Signer::Demo::PUBKEY, PayKit.config.operator.effective_recipient
  end

  def test_default_x402_facilitator_url_is_nil_and_self_hosted
    PayKit.configure { |_c| }
    assert_nil PayKit.config.x402.facilitator_url
    refute PayKit.config.x402.delegated?
  end

  # --- rpc_url ---------------------------------------------------------

  def test_rpc_url_defaults_per_network
    {
      solana_mainnet: "https://api.mainnet-beta.solana.com",
      solana_devnet: "https://api.devnet.solana.com",
      solana_localnet: "http://localhost:8899"
    }.each do |network, expected|
      PayKit.reset!
      PayKit.configure do |c|
        c.network = network
        if network == :solana_mainnet
          # Avoid demo+mainnet refusal in this test.
          c.operator { |op| op.signer = PayKit::Signer.bytes((1..64).to_a) }
        end
      end
      assert_equal expected, PayKit.config.effective_rpc_url, "default rpc_url for #{network}"
      assert PayKit.config.using_public_rpc_default?
    end
  end

  def test_explicit_rpc_url_overrides_default
    PayKit.configure do |c|
      c.rpc_url = "https://helius.example.com"
    end
    assert_equal "https://helius.example.com", PayKit.config.effective_rpc_url
    refute PayKit.config.using_public_rpc_default?
  end

  # --- operator block + assignment ------------------------------------

  def test_operator_block_yields_current_operator_for_mutation
    PayKit.configure do |c|
      c.operator do |op|
        op.recipient = "ExplicitRecipient"
        op.fee_payer = false
      end
    end
    assert_equal "ExplicitRecipient", PayKit.config.operator.recipient
    refute PayKit.config.operator.fee_payer?
  end

  def test_operator_direct_assignment_replaces_object
    new_op = PayKit::Operator.new(recipient: "Direct", signer: PayKit::Signer.bytes((1..64).to_a))
    PayKit.configure { |c| c.operator = new_op }
    assert_equal "Direct", PayKit.config.operator.recipient
    refute PayKit.config.operator.signer.demo?
  end

  def test_operator_assignment_rejects_non_operator
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.operator = "not an operator" }
    end
  end

  # --- mainnet refusal + warnings -------------------------------------

  def test_mainnet_plus_demo_signer_raises
    assert_raises(PayKit::DemoSignerOnMainnetError) do
      PayKit.configure { |c| c.network = :solana_mainnet }
    end
  end

  def test_mainnet_plus_real_signer_does_not_raise
    PayKit.configure do |c|
      c.network = :solana_mainnet
      c.rpc_url = "https://my-private-rpc.example.com"
      c.operator { |op| op.signer = PayKit::Signer.bytes((1..64).to_a) }
    end
    refute_nil PayKit.config
  end

  def test_mainnet_plus_public_rpc_warns
    PayKit.configure do |c|
      c.network = :solana_mainnet
      c.operator { |op| op.signer = PayKit::Signer.bytes((1..64).to_a) }
    end
    assert(@captured_logs.any? { |line| line.include?("public Solana RPC") },
      "expected a public-RPC warning, got: #{@captured_logs.inspect}")
  end

  def test_devnet_plus_public_rpc_does_not_warn
    PayKit.configure do |c|
      c.network = :solana_devnet
    end
    refute(@captured_logs.any? { |line| line.include?("public Solana RPC") })
  end

  def test_mainnet_plus_explicit_rpc_does_not_warn
    PayKit.configure do |c|
      c.network = :solana_mainnet
      c.rpc_url = "https://private.example.com"
      c.operator { |op| op.signer = PayKit::Signer.bytes((1..64).to_a) }
    end
    refute(@captured_logs.any? { |line| line.include?("public Solana RPC") })
  end

  # --- x402 mode switch -----------------------------------------------

  def test_setting_facilitator_url_flips_delegated_predicate
    PayKit.configure { |c| c.x402.facilitator_url = "https://facilitator.example.com" }
    assert PayKit.config.x402.delegated?
    assert_equal "https://facilitator.example.com", PayKit.config.x402.facilitator_url
  end

  def test_empty_facilitator_url_is_not_delegated
    PayKit.configure { |c| c.x402.facilitator_url = "" }
    refute PayKit.config.x402.delegated?
  end

  # --- x402 signer override -------------------------------------------

  def test_x402_signer_defaults_to_operator_signer
    PayKit.configure do |c|
      c.operator { |op| op.signer = PayKit::Signer.bytes((1..64).to_a) }
    end
    assert_equal PayKit.config.operator.signer, PayKit.config.x402.effective_signer
  end

  def test_x402_signer_overrides_operator_for_x402_only
    explicit = PayKit::Signer.bytes((1..64).to_a)
    PayKit.configure do |c|
      c.x402.signer = explicit
    end
    assert_equal explicit, PayKit.config.x402.effective_signer
    refute_equal explicit, PayKit.config.operator.signer
  end

  def test_x402_signer_setter_rejects_non_signer_like
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.x402.signer = Object.new }
    end
  end

  # --- challenge_binding_secret ---------------------------------------

  def test_challenge_binding_secret_setter_and_reader
    PayKit.configure { |c| c.mpp.challenge_binding_secret = "rotate-me" }
    assert_equal "rotate-me", PayKit.config.mpp.challenge_binding_secret
  end

  def test_mpp_expires_in_default_and_override
    PayKit.configure { |_c| }
    assert_equal 300, PayKit.config.mpp.expires_in

    PayKit.reset!
    PayKit.configure { |c| c.mpp.expires_in = 600 }
    assert_equal 600, PayKit.config.mpp.expires_in
  end

  # --- deprecation shims ----------------------------------------------

  def test_pay_to_shim_routes_to_operator_recipient_and_warns
    PayKit.configure { |c| c.pay_to = "ShimmedRecipient" }
    assert_equal "ShimmedRecipient", PayKit.config.operator.recipient
    assert(@captured_logs.any? { |line| line.include?("c.pay_to=") && line.include?("deprecated") })
  end

  def test_x402_facilitator_shim_routes_to_rpc_url_and_warns
    PayKit.configure { |c| c.x402.facilitator = "http://shimmed-rpc.example.com" }
    assert_equal "http://shimmed-rpc.example.com", PayKit.config.effective_rpc_url
    assert(@captured_logs.any? { |line| line.include?("c.x402.facilitator=") && line.include?("rpc_url") })
  end

  def test_x402_facilitator_secret_key_shim_routes_to_operator_signer
    bytes_json = JSON.generate((1..64).to_a)
    PayKit.configure { |c| c.x402.facilitator_secret_key = bytes_json }
    expected_pubkey = PayCore::Solana::Account.new((1..64).to_a).public_key.to_s
    assert_equal expected_pubkey, PayKit.config.operator.signer.pubkey
    assert(@captured_logs.any? { |line| line.include?("c.x402.facilitator_secret_key=") })
  end

  def test_x402_facilitator_secret_key_shim_treats_empty_array_as_noop
    PayKit.configure { |c| c.x402.facilitator_secret_key = "[]" }
    # Operator still has the default demo signer untouched.
    assert PayKit.config.operator.signer.demo?
  end

  def test_x402_facilitator_secret_key_shim_treats_nil_as_noop
    PayKit.configure { |c| c.x402.facilitator_secret_key = nil }
    assert PayKit.config.operator.signer.demo?
  end

  def test_x402_facilitator_secret_key_shim_reader_returns_signer_json
    bytes_json = JSON.generate((1..64).to_a)
    PayKit.configure { |c| c.x402.facilitator_secret_key = bytes_json }
    assert_equal bytes_json, PayKit.config.x402.facilitator_secret_key
  end

  def test_x402_facilitator_shim_reader_returns_effective_rpc_url
    PayKit.configure { |c| c.rpc_url = "https://rpc.example.com" }
    assert_equal "https://rpc.example.com", PayKit.config.x402.facilitator
  end

  def test_mpp_secret_shim_reader_returns_challenge_binding_secret
    PayKit.configure { |c| c.mpp.challenge_binding_secret = "shared" }
    assert_equal "shared", PayKit.config.mpp.secret
  end

  def test_x402_facilitator_secret_key_shim_treats_empty_string_as_noop
    PayKit.configure { |c| c.x402.facilitator_secret_key = "" }
    assert PayKit.config.operator.signer.demo?
  end

  def test_mpp_secret_shim_routes_to_challenge_binding_secret_and_warns
    PayKit.configure { |c| c.mpp.secret = "shimmed-secret" }
    assert_equal "shimmed-secret", PayKit.config.mpp.challenge_binding_secret
    assert(@captured_logs.any? { |line| line.include?("c.mpp.secret=") && line.include?("challenge_binding_secret") })
  end

  def test_each_deprecation_warning_fires_only_once_per_process
    PayKit.configure do |c|
      c.pay_to = "First"
      c.pay_to = "Second"
      c.pay_to = "Third"
    end
    matching = @captured_logs.count { |line| line.include?("c.pay_to=") }
    assert_equal 1, matching, "deprecation should warn once: #{@captured_logs.inspect}"
  end

  # --- legacy validations still hold ----------------------------------

  def test_configure_freezes_config_and_subconfigs
    PayKit.configure { |c| c.mpp.challenge_binding_secret = "x" }
    assert PayKit.config.frozen?
    assert PayKit.config.x402.frozen?
    assert PayKit.config.mpp.frozen?
  end

  def test_invalid_network_raises
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.network = :bitcoin }
    end
  end

  def test_invalid_scheme_in_accept_raises
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.accept = %i[stripe] }
    end
  end

  def test_empty_accept_raises
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.accept = [] }
    end
  end

  def test_empty_stablecoins_raises
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.stablecoins = [] }
    end
  end

  def test_invalid_x402_scheme_raises
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.x402.scheme = :upto }
    end
  end

  def test_pricing_setter_freezes_registry
    PayKitTestHelpers.with_config do
      klass = Class.new(PayKit::Pricing) do
        def build_gates
          gate :a, amount: usd("0.10")
        end
      end
      PayKit.pricing = klass.new
      assert PayKit.pricing.frozen?
    end
  end

  private

  # Captures every line passed to the logger so individual tests can
  # assert on warning emission without polluting test output.
  def capture_logger(sink)
    Class.new do
      def initialize(sink)
        @sink = sink
      end

      def warn(msg = nil)
        msg = yield if block_given?
        @sink << msg
      end

      def info(msg = nil)
        msg = yield if block_given?
        @sink << msg
      end

      def debug(*)
      end

      def error(*)
      end
    end.new(sink)
  end
end
