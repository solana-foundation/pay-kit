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
        external_id: ctx._external_id,
        default_pay_to: @defaults[:pay_to],
        accept_default: @defaults[:accept]
      )
    end

    # NOTE: `fees?` deliberately not defined here. A DynamicGate can't
    # answer "do I have fees?" without a request to evaluate the
    # builder block against. Callers must materialize first (the
    # Sinatra helper at `resolve_gate` does this automatically, and
    # `Dispatcher#materialize` is the explicit hook). The previous
    # `fees? = true` shortcut was a defensive lie that silently
    # disabled x402 for every dynamic gate, even those that resolve
    # to zero fees on a given request.

    # Setter sink used inside the dynamic block. The block calls
    # `amount usd("0.10")`, `pay_to ALICE`, etc.; reads back via
    # `_amount`/`_pay_to`/... when resolve runs.
    class DynamicContext
      include Helpers::Pricing

      attr_reader :_amount, :_pay_to, :_fee_within, :_fee_on_top, :_external_id

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

      # Per-request external identifier (order ID, invoice number, etc).
      # Surfaced on the MPP charge so receipts and downstream audit
      # systems can correlate the on-chain settlement with the merchant's
      # own record. Optional; nil when not set.
      def external_id(value)
        @_external_id = value
      end

      def apply(request, &block)
        instance_exec request, &block
      end
    end
  end
end
