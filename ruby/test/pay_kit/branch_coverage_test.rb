# frozen_string_literal: true

require_relative "test_helper"

# Targeted tests for branches not exercised by the primary test files.
# Each test names the specific branch it covers.
class PayKitBranchCoverageTest < Minitest::Test
  def teardown
    PayKit.reset!
  end

  # --- price.rb ---

  def test_settlement_to_s
    s = PayKit::Settlement.new(coin: :USDC, amount: "1.00")
    assert_equal "1.00 USDC", s.to_s
  end

  def test_price_to_s
    PayKitTestHelpers.with_config do
      price = PayKit::Price.build(denom: :USD, amount: "1.00", coins: [:USDC, :USDT])
      assert_includes price.to_s, "USD 1.00"
      assert_includes price.to_s, "USDC"
    end
  end

  def test_price_primary_coin_returns_first_settlement_coin
    PayKitTestHelpers.with_config do
      price = PayKit::Price.build(denom: :USD, amount: "1.00", coins: [:USDC, :USDT])
      assert_equal :USDC, price.primary_coin
    end
  end

  def test_helpers_pricing_raises_when_no_coins_and_config_missing_stablecoins
    # Force PayKit.config.stablecoins to be empty.
    PayKit.reset!
    cfg = PayKit::Config.new
    PayKit.instance_variable_set(:@config, cfg)
    cfg.instance_variable_set(:@stablecoins, [].freeze)

    helper = Class.new { include PayKit::Helpers::Pricing }.new
    assert_raises(PayKit::ConfigurationError) { helper.usd("0.10") }
  end

  def test_price_rejects_empty_amount_string
    assert_raises(PayKit::ConfigurationError) do
      PayKit::Price.new(
        denom: :USD,
        amount: "",
        settlements: [PayKit::Settlement.new(coin: :USDC, amount: "1.00")]
      )
    end
  end

  def test_price_rejects_non_settlement_in_settlements_array
    assert_raises(PayKit::ConfigurationError) do
      PayKit::Price.new(denom: :USD, amount: "1.00", settlements: ["not_a_settlement"])
    end
  end

  def test_pricing_setter_freezes_non_frozen_registry
    PayKitTestHelpers.with_config do
      # A plain Object that is not frozen exercises the
      # "registry.freeze unless registry.frozen?" branch where the
      # condition is true (not yet frozen, do freeze).
      registry = Object.new
      refute registry.frozen?
      PayKit.pricing = registry
      assert registry.frozen?
    end
  end

  def test_eur_and_gbp_helpers
    PayKitTestHelpers.with_config(stablecoins: %i[USDC]) do
      helper = Class.new { include PayKit::Helpers::Pricing }.new
      assert_equal :EUR, helper.eur("1.00", :USDC).denom
      assert_equal :GBP, helper.gbp("1.00", :USDC).denom
    end
  end

  # --- fee.rb ---

  def test_fee_builder_returns_empty_for_nil
    assert_equal [], PayKit::FeeBuilder.from_hash(nil, kind: :within)
  end

  def test_fee_builder_rejects_non_hash
    assert_raises(PayKit::ConfigurationError) do
      PayKit::FeeBuilder.from_hash([], kind: :within)
    end
  end

  def test_fee_builder_rejects_non_string_recipient
    PayKitTestHelpers.with_config do
      price = PayKit::Price.build(denom: :USD, amount: "1.00", coins: [:USDC])
      assert_raises(PayKit::ConfigurationError) do
        PayKit::FeeBuilder.from_hash({123 => price}, kind: :within)
      end
    end
  end

  def test_fee_builder_rejects_non_price_value
    assert_raises(PayKit::ConfigurationError) do
      PayKit::FeeBuilder.from_hash({"r" => "1.00"}, kind: :within)
    end
  end

  def test_fee_within_and_on_top_predicates
    PayKitTestHelpers.with_config do
      price = PayKit::Price.build(denom: :USD, amount: "1.00", coins: [:USDC])
      within = PayKit::Fee.new(recipient: "x", price: price, kind: :within)
      on_top = PayKit::Fee.new(recipient: "y", price: price, kind: :on_top)
      assert within.within?
      refute within.on_top?
      assert on_top.on_top?
      refute on_top.within?
    end
  end

  # --- gate.rb ---

  def test_gate_non_symbol_name_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      helper = Class.new { include PayKit::Helpers::Pricing }.new
      assert_raises(PayKit::ConfigurationError) do
        PayKit::Gate.build(name: "not_symbol", amount: helper.usd("0.10"), default_pay_to: "x", accept_default: %i[mpp])
      end
    end
  end

  def test_gate_non_price_amount_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      assert_raises(PayKit::ConfigurationError) do
        PayKit::Gate.build(name: :bad, amount: "0.10", default_pay_to: "x", accept_default: %i[mpp])
      end
    end
  end

  def test_gate_empty_accept_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      helper = Class.new { include PayKit::Helpers::Pricing }.new
      assert_raises(PayKit::ConfigurationError) do
        PayKit::Gate.build(name: :bad, amount: helper.usd("0.10"), pay_to: "x", accept: [],
          default_pay_to: "x", accept_default: [])
      end
    end
  end

  # --- pricing.rb ---

  def test_coerce_raises_when_symbol_passed_without_registry
    PayKit.reset!
    PayKit.configure do |c|
      c.pay_to = "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"
      c.mpp.secret = "x"
    end
    assert_raises(PayKit::NoRegistryConfigured) do
      PayKit::Pricing.coerce(:something, registry: nil)
    end
  end

  def test_pricing_each_iterates_gates
    klass = Class.new(PayKit::Pricing) do
      def build_gates
        gate :a, amount: usd("0.10")
        gate :b, amount: usd("0.20")
      end
    end
    PayKitTestHelpers.with_config do
      pricing = klass.new
      names = pricing.to_a.map(&:name)
      assert_equal [:a, :b], names
      assert pricing.include?(:a)
      refute pricing.include?(:nope)
      yielded = []
      pricing.each { |g| yielded << g.name }
      assert_equal [:a, :b], yielded
    end
  end

  # --- config.rb ---

  def test_unknown_network_symbol_raises
    PayKit.reset!
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.network = :ethereum_mainnet }
    end
  end

  def test_x402_scheme_setter_accepts_exact
    PayKit.reset!
    PayKit.configure do |c|
      c.pay_to = "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"
      c.mpp.secret = "x"
      c.x402.scheme = :exact
    end
    assert_equal :exact, PayKit.config.x402.scheme
  end

  def test_pricing_setter_idempotent_on_already_frozen_registry
    klass = Class.new(PayKit::Pricing) do
      def build_gates
        gate :a, amount: usd("0.10")
      end
    end

    PayKitTestHelpers.with_config do
      pricing = klass.new
      assert pricing.frozen?
      # Should not raise on the second assignment of an already-frozen
      # registry (the freeze-unless-frozen branch).
      PayKit.pricing = pricing
      PayKit.pricing = pricing
    end
  end

  def test_x402_unknown_scheme_raises
    PayKit.reset!
    assert_raises(PayKit::ConfigurationError) do
      PayKit.configure { |c| c.x402.scheme = :batch }
    end
  end

  # --- challenge.rb ---

  def test_challenge_to_h_shape
    challenge = PayKit::Challenge.new(resource: "/x", accepts: [{a: 1}], headers: {})
    body = challenge.to_h
    assert_equal "payment_required", body[:error]
    assert_equal "/x", body[:resource]
    assert_equal [{a: 1}], body[:accepts]
  end

  def test_payment_protocol_predicates
    payment = PayKit::Payment.new(protocol: :x402, scheme: :exact,
      transaction: "sig", settlement_headers: {}, raw: "raw")
    assert payment.x402?
    refute payment.mpp?
  end

  # --- errors.rb ---

  def test_payment_required_carries_challenge
    challenge = PayKit::Challenge.new(resource: "/x", accepts: [], headers: {})
    error = PayKit::PaymentRequired.new(challenge)
    assert_equal challenge, error.challenge
    assert_match(/payment required/, error.message)
  end

  def test_invalid_proof_carries_code_and_detail
    error = PayKit::InvalidProof.new(:payment_invalid, "bad sig")
    assert_equal :payment_invalid, error.code
    assert_equal "bad sig", error.detail
    assert_equal "bad sig", error.message
  end

  def test_unknown_gate_message_includes_name
    error = PayKit::UnknownGate.new(:typo)
    assert_match(/typo/, error.message)
  end
end
