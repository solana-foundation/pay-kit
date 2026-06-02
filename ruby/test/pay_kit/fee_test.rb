# frozen_string_literal: true

require_relative "test_helper"

class PayKitFeeTest < Minitest::Test
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
      price = PayKit::Price.build(currency: :USD, amount: "1.00", coins: [:USDC])
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
      price = PayKit::Price.build(currency: :USD, amount: "1.00", coins: [:USDC])
      within = PayKit::Fee.new(recipient: "x", price: price, kind: :within)
      on_top = PayKit::Fee.new(recipient: "y", price: price, kind: :on_top)
      assert within.within?
      refute within.on_top?
      assert on_top.on_top?
      refute on_top.within?
    end
  end
end
