# frozen_string_literal: true

require_relative "errors"
require_relative "price"
require_relative "gate"

module PayKit
  # Dynamic gate: the amount and fees come from a Proc evaluated per
  # request. The Proc runs against `DynamicContext` which exposes
  # the same DSL setters (`amount`, `pay_to`, `fee_within`, `fee_on_top`)
  # as the class-level `gate ...` declaration.
  class DynamicGate
    attr_reader :name, :accept, :description

    def initialize(name:, accept:, description:, builder:, defaults:)
      @name = name
      @accept = accept
      @description = description
      @builder = builder
      @defaults = defaults
      freeze
    end

    def resolve(request)
      ctx = DynamicContext.new
      ctx.apply(request, &@builder)
      Gate.build(
        name: name,
        amount: ctx._amount || (raise ConfigurationError, "dynamic gate #{name.inspect}: amount not set"),
        pay_to: ctx._pay_to,
        fee_within: ctx._fee_within,
        fee_on_top: ctx._fee_on_top,
        accept: accept,
        description: description,
        default_pay_to: @defaults[:pay_to],
        accept_default: @defaults[:accept]
      )
    end

    def fees?
      true
    end

    # Setter sink used inside the dynamic block. The block calls
    # `amount usd("0.10")`, `pay_to ALICE`, etc.; reads back via
    # `_amount`/`_pay_to`/... when resolve runs.
    class DynamicContext
      include Helpers::Pricing

      attr_reader :_amount, :_pay_to, :_fee_within, :_fee_on_top

      def amount(price)
        @_amount = price
      end

      def pay_to(address)
        @_pay_to = address
      end

      def fee_within(hash)
        @_fee_within = hash
      end

      def fee_on_top(hash)
        @_fee_on_top = hash
      end

      def apply(request, &block)
        instance_exec request, &block
      end
    end
  end
end
