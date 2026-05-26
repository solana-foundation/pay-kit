# frozen_string_literal: true

require_relative "test_helper"

class PayKitGateTest < Minitest::Test
  SELLER = "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"
  PLATFORM = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
  GATEWAY = "9rTLpzUDg3wePV8R45MQyHWFFiLBzgsJrePmDQVQGqAH"

  def setup
    @helper_klass = Class.new { include PayKit::Helpers::Pricing }
  end

  def test_simple_gate_inherits_config_defaults
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      gate = build(:report, amount: usd("0.10"))

      assert_equal :report, gate.name
      assert_equal "0.10", gate.amount.amount
      assert_equal [:mpp], gate.accept
      refute gate.fees?
    end
  end

  def test_gate_total_equals_amount_when_no_fees
    PayKitTestHelpers.with_config do
      gate = build(:report, amount: usd("0.10"))
      assert_equal "0.10", gate.total.amount
    end
  end

  def test_fee_within_reduces_pay_to_payout
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      gate = build(:sale,
        amount: usd("10.00"),
        pay_to: SELLER,
        fee_within: {PLATFORM => usd("0.30")})

      assert_equal "10.00", gate.total.amount
      assert_equal "9.7", gate.payout(to: SELLER).amount
      assert_equal "0.30", gate.payout(to: PLATFORM).amount
    end
  end

  def test_fee_on_top_increases_total
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      gate = build(:ticket,
        amount: usd("10.00"),
        pay_to: SELLER,
        fee_on_top: {PLATFORM => usd("0.50")})

      assert_equal "10.5", gate.total.amount
      assert_equal "10.00", gate.payout(to: SELLER).amount
      assert_equal "0.50", gate.payout(to: PLATFORM).amount
    end
  end

  def test_mixed_fees_combine_correctly
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      gate = build(:complex,
        amount: usd("100.00"),
        pay_to: SELLER,
        fee_within: {PLATFORM => usd("3.00")},
        fee_on_top: {GATEWAY => usd("0.50")})

      assert_equal "100.5", gate.total.amount
      assert_equal "97", gate.payout(to: SELLER).amount
      assert_equal "3.00", gate.payout(to: PLATFORM).amount
      assert_equal "0.50", gate.payout(to: GATEWAY).amount
    end
  end

  def test_unknown_payout_recipient_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      gate = build(:report, amount: usd("0.10"))
      assert_raises(PayKit::ConfigurationError) { gate.payout(to: "stranger") }
    end
  end

  def test_x402_auto_disabled_when_fees_present
    PayKitTestHelpers.with_config(accept: %i[x402 mpp]) do
      gate = build(:sale,
        amount: usd("10.00"),
        pay_to: SELLER,
        fee_within: {PLATFORM => usd("1.00")})

      refute gate.x402_accepted?
      assert gate.mpp_accepted?
    end
  end

  def test_explicit_x402_with_fees_raises
    PayKitTestHelpers.with_config(accept: %i[x402 mpp]) do
      assert_raises(PayKit::ConfigurationError) do
        build(:bad,
          amount: usd("10.00"),
          pay_to: SELLER,
          accept: %i[x402 mpp],
          fee_within: {PLATFORM => usd("1.00")})
      end
    end
  end

  def test_self_referential_fee_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      assert_raises(PayKit::ConfigurationError) do
        build(:bad,
          amount: usd("10.00"),
          pay_to: SELLER,
          fee_within: {SELLER => usd("1.00")})
      end
    end
  end

  def test_within_sum_exceeding_amount_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      assert_raises(PayKit::ConfigurationError) do
        build(:bad,
          amount: usd("1.00"),
          pay_to: SELLER,
          fee_within: {PLATFORM => usd("2.00")})
      end
    end
  end

  def test_mixed_denominations_raise
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      assert_raises(PayKit::ConfigurationError) do
        PayKit::Gate.build(
          name: :bad,
          amount: usd("10.00"),
          pay_to: SELLER,
          fee_within: {PLATFORM => @helper_klass.new.eur("1.00", :USDC)},
          accept_default: %i[mpp],
          default_pay_to: SELLER
        )
      end
    end
  end

  def test_duplicate_fee_recipient_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      assert_raises(PayKit::ConfigurationError) do
        PayKit::Gate.build(
          name: :bad,
          amount: usd("10.00"),
          pay_to: SELLER,
          fee_within: {PLATFORM => usd("1.00")},
          fee_on_top: {PLATFORM => usd("0.50")},
          accept_default: %i[mpp],
          default_pay_to: SELLER
        )
      end
    end
  end

  def test_gate_frozen
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      gate = build(:report, amount: usd("0.10"))
      assert gate.frozen?
      assert gate.fees.frozen?
      assert gate.accept.frozen?
    end
  end

  def test_fees_with_x402_only_config_raises_empty_accept
    PayKitTestHelpers.with_config(accept: %i[x402]) do
      assert_raises(PayKit::ConfigurationError) do
        build(:bad,
          amount: usd("10.00"),
          pay_to: SELLER,
          fee_within: {PLATFORM => usd("1.00")})
      end
    end
  end

  def test_missing_pay_to_raises
    PayKitTestHelpers.with_config(accept: %i[mpp]) do
      assert_raises(PayKit::ConfigurationError) do
        PayKit::Gate.build(name: :no_pay_to, amount: usd("0.10"), accept_default: %i[mpp])
      end
    end
  end

  private

  def build(name, amount:, pay_to: nil, accept: nil, fee_within: nil, fee_on_top: nil, description: nil)
    PayKit::Gate.build(
      name: name,
      amount: amount,
      pay_to: pay_to,
      accept: accept,
      fee_within: fee_within,
      fee_on_top: fee_on_top,
      description: description,
      accept_default: PayKit.config.accept,
      default_pay_to: PayKit.config.pay_to
    )
  end

  def usd(amount, *coins)
    @helper_klass.new.usd(amount, *coins)
  end
end
