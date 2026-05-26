# frozen_string_literal: true

require_relative "test_helper"

class PayKitPricingTest < Minitest::Test
  class MyPricing < PayKit::Pricing
    def build_gates
      gate :free_lookup, amount: usd("0.10")
      gate :two_coin, amount: usd("1.00", :USDC, :USDT), accept: :x402

      gate :dyn do |req|
        amount usd((req.params["tier"] == "premium") ? "5.00" : "0.10")
      end
    end
  end

  def test_registry_resolves_known_gate
    PayKitTestHelpers.with_config do
      pricing = MyPricing.new
      gate = pricing[:free_lookup]
      assert_equal :free_lookup, gate.name
    end
  end

  def test_registry_raises_unknown_gate
    PayKitTestHelpers.with_config do
      assert_raises(PayKit::UnknownGate) { MyPricing.new[:nope] }
    end
  end

  def test_registry_frozen_after_build
    PayKitTestHelpers.with_config do
      pricing = MyPricing.new
      assert pricing.frozen?
    end
  end

  def test_dynamic_gate_resolves_per_request
    PayKitTestHelpers.with_config do
      pricing = MyPricing.new
      dyn = pricing[:dyn]
      assert_kind_of PayKit::DynamicGate, dyn

      mock_request = Struct.new(:params)
      basic_request = mock_request.new({"tier" => "basic"})
      premium_request = mock_request.new({"tier" => "premium"})

      assert_equal "0.10", dyn.resolve(basic_request).amount.amount
      assert_equal "5.00", dyn.resolve(premium_request).amount.amount
    end
  end

  def test_coerce_passes_through_gate
    PayKitTestHelpers.with_config do
      pricing = MyPricing.new
      PayKit.pricing = pricing

      gate = pricing[:free_lookup]
      same = PayKit::Pricing.coerce(gate, registry: pricing)
      assert_same gate, same
    end
  end

  def test_coerce_resolves_symbol_via_registry
    PayKitTestHelpers.with_config do
      pricing = MyPricing.new
      PayKit.pricing = pricing
      gate = PayKit::Pricing.coerce(:free_lookup, registry: pricing)
      assert_equal :free_lookup, gate.name
    end
  end

  def test_coerce_wraps_inline_price_in_anonymous_gate
    PayKitTestHelpers.with_config do
      helper = Class.new { include PayKit::Helpers::Pricing }.new
      gate = PayKit::Pricing.coerce(helper.usd("0.25"), inline_defaults: {description: "Inline"})
      assert_equal "0.25", gate.amount.amount
      assert_equal "Inline", gate.description
    end
  end

  def test_coerce_raises_on_garbage
    PayKitTestHelpers.with_config do
      assert_raises(PayKit::ConfigurationError) { PayKit::Pricing.coerce(42) }
    end
  end

  def test_duplicate_gate_raises_at_boot
    duplicate_pricing = Class.new(PayKit::Pricing) do
      def build_gates
        gate :foo, amount: usd("0.10")
        gate :foo, amount: usd("0.20")
      end
    end

    PayKitTestHelpers.with_config do
      assert_raises(PayKit::ConfigurationError) { duplicate_pricing.new }
    end
  end
end
