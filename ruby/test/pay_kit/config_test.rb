# frozen_string_literal: true

require_relative "test_helper"

class PayKitConfigTest < Minitest::Test
  def teardown
    PayKit.reset!
  end

  def test_configure_freezes_config
    PayKit.configure do |c|
      c.pay_to = "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"
      c.mpp.secret = "x"
    end
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
end
