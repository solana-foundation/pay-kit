# frozen_string_literal: true

require "bigdecimal"

require_relative "errors"

module PayKit
  # A single settlement preference: pay `amount` denominated in `coin`.
  # v1 always sets `amount` equal across a `Price`'s settlements; the
  # shape leaves room for per-coin overrides later (rule 5 in design).
  Settlement = Data.define(:coin, :amount) do
    def to_s
      "#{amount} #{coin}"
    end
  end

  # Denomination + ordered settlement preference list.
  #
  #   Price.new(denom: :USD, amount: "0.10", settlements: [Settlement(coin: :USDC, amount: "0.10")])
  #
  # Build via the `usd("0.10", :USDC, :USDT)` shorthand (see
  # PayKit::Helpers::Pricing). `settlements` is always non-empty; the
  # first entry is the preference.
  class Price
    attr_reader :denom, :amount, :settlements

    def initialize(denom:, amount:, settlements:)
      raise ConfigurationError, "denom must be a symbol like :USD" unless denom.is_a?(Symbol)
      raise ConfigurationError, "amount must be a non-empty string" unless amount.is_a?(String) && !amount.empty?
      raise ConfigurationError, "settlements must be a non-empty array" if !settlements.is_a?(Array) || settlements.empty?
      unless settlements.all? { |s| s.is_a?(Settlement) }
        raise ConfigurationError, "settlements must be Settlement objects"
      end

      @denom = denom
      @amount = amount
      @settlements = settlements.freeze
      freeze
    end

    # Build a Price denominated in `denom` from the variadic
    # `coins` list. Empty list means "use config defaults" and
    # is filled in later by the Pricing DSL.
    def self.build(denom:, amount:, coins: [])
      settlements = coins.flatten.compact.map { |coin| Settlement.new(coin: coin.to_sym, amount: amount) }
      new(denom: denom, amount: amount, settlements: settlements)
    end

    # The primary settlement coin (first preference). Used by
    # single-recipient flows where only the top choice matters.
    # Settlements is guaranteed non-empty by `Price.new`.
    def primary_coin
      settlements.first.coin
    end

    def to_s
      "#{denom} #{amount} (#{settlements.map(&:coin).join(", ")})"
    end

    # Numeric amount for fee math. BigDecimal-precise. Recomputed
    # per call so the frozen Price stays frozen.
    def to_d
      raise ConfigurationError, "invalid amount: #{amount.inspect}" unless /\A\d+(\.\d+)?\z/.match?(amount)

      BigDecimal(amount)
    end

    # Build a new Price with the same denom and a different amount.
    # Settlements list reuses the existing coin order.
    def with_amount(new_amount)
      Price.new(
        denom: denom,
        amount: new_amount.to_s,
        settlements: settlements.map { |s| Settlement.new(coin: s.coin, amount: new_amount.to_s) }
      )
    end
  end

  module Helpers
    # Mixed into the Pricing DSL and into controller helpers so
    # `usd("0.10")` works in both call sites. When no coins are
    # passed explicitly, falls back to `PayKit.config.stablecoins`.
    module Pricing
      def usd(amount, *coins)
        ::PayKit::Helpers::Pricing.build_price(:USD, amount, coins)
      end

      def eur(amount, *coins)
        ::PayKit::Helpers::Pricing.build_price(:EUR, amount, coins)
      end

      def gbp(amount, *coins)
        ::PayKit::Helpers::Pricing.build_price(:GBP, amount, coins)
      end

      def self.build_price(denom, amount, coins)
        resolved = coins.flatten.compact
        if resolved.empty?
          resolved = ::PayKit.config.stablecoins
          if resolved.empty?
            raise ::PayKit::ConfigurationError,
              "no stablecoins specified and PayKit.config.stablecoins is empty"
          end
        end
        ::PayKit::Price.build(denom: denom, amount: amount.to_s, coins: resolved)
      end
    end
  end
end
