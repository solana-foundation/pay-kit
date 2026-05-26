# frozen_string_literal: true

require_relative "test_helper"

class PayKitPriceTest < Minitest::Test
  def test_usd_helper_falls_back_to_config_stablecoins
    PayKitTestHelpers.with_config(stablecoins: %i[USDC USDT]) do
      price = Class.new { include PayKit::Helpers::Pricing }.new.usd("0.10")

      assert_equal :USD, price.denom
      assert_equal "0.10", price.amount
      assert_equal [:USDC, :USDT], price.settlements.map(&:coin)
    end
  end

  def test_usd_helper_takes_explicit_coins
    PayKitTestHelpers.with_config do
      price = Class.new { include PayKit::Helpers::Pricing }.new.usd("1.00", :USDC, :USDT)

      assert_equal [:USDC, :USDT], price.settlements.map(&:coin)
      assert(price.settlements.all? { |s| s.amount == "1.00" })
    end
  end

  def test_usd_helper_flattens_array_argument
    PayKitTestHelpers.with_config do
      price = Class.new { include PayKit::Helpers::Pricing }.new.usd("0.10", *%i[USDC USDT])
      assert_equal [:USDC, :USDT], price.settlements.map(&:coin)
    end
  end

  def test_price_to_d_is_bigdecimal_precise
    require "bigdecimal"
    PayKitTestHelpers.with_config do
      price = PayKit::Price.build(denom: :USD, amount: "0.10", coins: [:USDC])
      assert_kind_of BigDecimal, price.to_d
      assert_equal BigDecimal("0.10"), price.to_d
    end
  end

  def test_price_rejects_non_decimal_amount
    PayKitTestHelpers.with_config do
      price = PayKit::Price.new(
        denom: :USD,
        amount: "nope",
        settlements: [PayKit::Settlement.new(coin: :USDC, amount: "nope")]
      )
      assert_raises(PayKit::ConfigurationError) { price.to_d }
    end
  end

  def test_price_rejects_empty_settlements
    assert_raises(PayKit::ConfigurationError) do
      PayKit::Price.new(denom: :USD, amount: "1.00", settlements: [])
    end
  end

  def test_price_rejects_non_symbol_denom
    assert_raises(PayKit::ConfigurationError) do
      PayKit::Price.new(
        denom: "USD",
        amount: "1.00",
        settlements: [PayKit::Settlement.new(coin: :USDC, amount: "1.00")]
      )
    end
  end

  def test_price_with_amount_preserves_coin_order
    PayKitTestHelpers.with_config do
      price = PayKit::Price.build(denom: :USD, amount: "1.00", coins: [:USDC, :USDT])
      replaced = price.with_amount("2.50")

      assert_equal "2.50", replaced.amount
      assert_equal [:USDC, :USDT], replaced.settlements.map(&:coin)
      assert(replaced.settlements.all? { |s| s.amount == "2.50" })
    end
  end

  def test_price_frozen
    PayKitTestHelpers.with_config do
      price = PayKit::Price.build(denom: :USD, amount: "1.00", coins: [:USDC])
      assert price.frozen?
      assert price.settlements.frozen?
    end
  end
end
