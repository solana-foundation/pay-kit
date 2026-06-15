# frozen_string_literal: true

require_relative "test_helper"

class PayKitConfigTest < Minitest::Test
  def setup
    PayKit.reset!
    @captured_logs = []
    PayKit.logger = capture_logger(@captured_logs)
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
      solana_localnet: "https://402.surfnet.dev:8899"
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

  # --- validations -----------------------------------------------------

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

  def test_invalid_protocol_in_accept_raises
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

  # --- preflight knob --------------------------------------------------

  def test_preflight_skipped_when_disabled_via_setter
    # `c.preflight = false` short-circuits `run_preflight` before it ever
    # tries to load `lib/pay_kit/preflight.rb` or open an RPC socket.
    preflight_called = false
    stub_preflight(captured: -> { preflight_called = true }) do
      with_env("PAY_KIT_DISABLE_PREFLIGHT" => nil) do
        PayKit.configure { |c| c.preflight = false }
      end
    end
    refute preflight_called, "Preflight.run must not be invoked when c.preflight = false"
  end

  def test_preflight_runs_when_env_opt_out_absent
    # The env-var opt-out is for the gem's own test suite (`test_helper`
    # sets `PAY_KIT_DISABLE_PREFLIGHT=1`). When the env var is absent
    # and `c.preflight` stays at its default `true`, `run_preflight`
    # falls through to `Preflight.run`.
    preflight_called = false
    stub_preflight(captured: -> { preflight_called = true }) do
      with_env("PAY_KIT_DISABLE_PREFLIGHT" => nil) do
        PayKit.configure { |_c| }
      end
    end
    assert preflight_called, "Preflight.run must run when neither flag opts out"
  end

  def test_unknown_network_symbol_raises
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.network = :ethereum_mainnet }
    end
  end

  def test_x402_scheme_setter_accepts_exact
    PayKit.configure do |c|
      c.operator { |op| op.recipient = "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj" }
      c.mpp.challenge_binding_secret = "x"
      c.x402.scheme = :exact
    end
    assert_equal :exact, PayKit.config.x402.scheme
  end

  def test_x402_unknown_scheme_raises
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.x402.scheme = :batch }
    end
  end

  private

  # Replace `PayKit::Preflight.run` with a no-op spy for the duration of
  # the block. Hides the live RPC call behind a deterministic stub so
  # the coverage tests do not need network access.
  def stub_preflight(captured:)
    require_relative "../../lib/pay_kit/preflight"
    original = PayKit::Preflight.method(:run)
    PayKit::Preflight.define_singleton_method(:run) { |_config| captured.call }
    yield
  ensure
    PayKit::Preflight.define_singleton_method(:run, original) if original
  end

  def with_env(overrides)
    previous = overrides.transform_values { |_| nil }
    overrides.each_key { |k| previous[k] = ENV[k] }
    overrides.each { |k, v| ENV[k] = v }
    yield
  ensure
    previous.each { |k, v| ENV[k] = v }
  end

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
