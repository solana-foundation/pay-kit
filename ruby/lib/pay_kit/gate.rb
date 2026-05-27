# frozen_string_literal: true

require_relative "errors"
require_relative "price"
require_relative "fee"

module PayKit
  # A single protected unit. Boot-time frozen value object. Carries
  # the base amount, optional fees, accepted schemes, pay_to recipient,
  # and human description. Dynamic gates wrap a Proc instead of being
  # frozen here (see DynamicGate).
  class Gate
    attr_reader :name, :amount, :pay_to, :fees, :accept, :description, :external_id

    def initialize(name:, amount:, pay_to:, fees:, accept:, description: nil, external_id: nil)
      @name = name
      @amount = amount
      @pay_to = pay_to
      @fees = fees
      @accept = accept
      @description = description
      @external_id = external_id
      freeze
    end

    # Build a Gate with full boot validation. `accept_default` and
    # `default_pay_to` come from PayKit.config when the DSL omits them.
    def self.build(name:, amount:, pay_to: nil, fee_within: nil, fee_on_top: nil,
      accept: nil, description: nil, external_id: nil,
      accept_default: nil, default_pay_to: nil)
      raise ConfigurationError, "gate name must be a Symbol, got #{name.inspect}" unless name.is_a?(Symbol)
      raise ConfigurationError, "gate #{name.inspect}: amount must be a Price (use usd/eur/gbp)" unless amount.is_a?(Price)

      resolved_pay_to = pay_to || default_pay_to
      unless resolved_pay_to.is_a?(String) && !resolved_pay_to.empty?
        raise ConfigurationError, "gate #{name.inspect}: pay_to is required (set on gate or in PayKit.configure)"
      end

      within_fees = FeeBuilder.from_hash(fee_within, kind: :within)
      on_top_fees = FeeBuilder.from_hash(fee_on_top, kind: :on_top)
      fees = (within_fees + on_top_fees).freeze

      validate_fee_recipients!(name, resolved_pay_to, fees)
      validate_denominations!(name, amount, fees)
      validate_within_sum!(name, amount, within_fees)

      resolved_accept = resolve_accept(name, accept, accept_default, fees)

      new(
        name: name,
        amount: amount,
        pay_to: resolved_pay_to,
        fees: fees,
        accept: resolved_accept,
        description: description,
        external_id: external_id
      )
    end

    # The amount the customer actually pays: base + sum of on-top fees.
    def total
      on_top_sum = fees.select(&:on_top?).map { |f| f.price.to_d }.sum
      return amount if on_top_sum.zero?

      amount.with_amount(Gate.format_decimal(amount.to_d + on_top_sum))
    end

    # What `recipient` nets from a paid request. For `pay_to`: amount
    # minus sum of `fee_within`. For a fee recipient: their fee. For
    # any other address: raises (typos shouldn't return 0 silently).
    def payout(to:)
      if to == pay_to
        within_sum = fees.select(&:within?).map { |f| f.price.to_d }.sum
        return amount if within_sum.zero?
        return amount.with_amount(Gate.format_decimal(amount.to_d - within_sum))
      end

      fee = fees.find { |f| f.recipient == to }
      return fee.price if fee

      raise ConfigurationError,
        "gate #{name.inspect}: payout(to: #{to.inspect}) - recipient is not pay_to and not in fees"
    end

    def fees?
      !fees.empty?
    end

    def x402_accepted?
      accept.include?(:x402)
    end

    def mpp_accepted?
      accept.include?(:mpp)
    end

    # Format a BigDecimal as a fixed-point decimal string, trimming
    # any trailing zeros after the decimal point but always keeping
    # at least one digit on either side.
    def self.format_decimal(value)
      s = value.to_s("F")
      whole, _, fraction = s.partition(".")
      fraction = fraction.sub(/0+\z/, "")
      fraction.empty? ? whole : "#{whole}.#{fraction}"
    end

    # --- internal validators -------------------------------------------

    def self.validate_fee_recipients!(name, pay_to, fees)
      fees.each do |fee|
        if fee.recipient == pay_to
          raise ConfigurationError,
            "gate #{name.inspect}: fee recipient #{pay_to.inspect} duplicates pay_to - fold the fee into amount instead"
        end
      end
      recipients = fees.map(&:recipient)
      duplicates = recipients.tally.select { |_, n| n > 1 }.keys
      unless duplicates.empty?
        raise ConfigurationError,
          "gate #{name.inspect}: duplicate fee recipient(s): #{duplicates.inspect}"
      end
    end

    def self.validate_denominations!(name, amount, fees)
      all_denoms = ([amount.denom] + fees.map { |f| f.price.denom }).uniq
      return if all_denoms.length <= 1

      raise ConfigurationError,
        "gate #{name.inspect}: all amounts must share one denomination, got #{all_denoms.inspect}"
    end

    def self.validate_within_sum!(name, amount, within_fees)
      return if within_fees.empty?

      within_sum = within_fees.map { |f| f.price.to_d }.sum
      return if within_sum <= amount.to_d

      raise ConfigurationError,
        "gate #{name.inspect}: sum(fee_within) = #{within_sum} exceeds amount #{amount.amount}"
    end

    def self.resolve_accept(name, accept, accept_default, fees)
      requested = Array(accept || accept_default).map(&:to_sym).uniq
      raise ConfigurationError, "gate #{name.inspect}: accept resolved to empty list" if requested.empty?

      if fees.any?
        if accept && Array(accept).map(&:to_sym).include?(:x402)
          raise ConfigurationError,
            "gate #{name.inspect}: x402 cannot be combined with fees (stock x402 facilitators settle to one address). Drop accept: :x402 or remove fees."
        end
        requested -= [:x402]
        if requested.empty?
          raise ConfigurationError,
            "gate #{name.inspect}: fees present and x402 auto-disabled - no remaining accepted schemes (add :mpp to PayKit.config.accept)"
        end
      end

      requested.freeze
    end
  end
end
