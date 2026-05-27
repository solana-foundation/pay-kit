# frozen_string_literal: true

require_relative "errors"
require_relative "price"
require_relative "gate"
require_relative "dynamic_gate"

module PayKit
  # Base class for the gates registry. Subclass and declare gates
  # in `initialize` using the `gate(...)` DSL.
  #
  #   class Pricing < PayKit::Pricing
  #     def initialize
  #       gate :report, amount: usd("0.10"), description: "Premium report"
  #     end
  #   end
  #
  #   PayKit.pricing = Pricing.new
  #
  # Registry is frozen at assignment. Lookups via `[name]` raise
  # `UnknownGate` for typos.
  class Pricing
    include Helpers::Pricing

    def initialize
      @gates = {}
      build_gates
      @gates.freeze
      freeze
    end

    # Subclasses MAY override `build_gates` instead of `initialize`
    # when they want the constructor signature intact. The default
    # implementation does nothing so subclasses that override
    # `initialize` keep working.
    def build_gates
    end

    def [](name)
      @gates.fetch(name.to_sym) { raise UnknownGate, name }
    end

    def fetch(name)
      self[name]
    end

    def include?(name)
      @gates.key?(name.to_sym)
    end

    def each(&block)
      @gates.each_value(&block)
    end

    def to_a
      @gates.values
    end

    # The DSL entry point used inside subclass constructors.
    #
    #   gate :report, amount: usd("0.10"), description: "..."
    #   gate :tiered do |req|
    #     amount usd(req.params[:tier] == "premium" ? "5.00" : "0.10")
    #   end
    def gate(name, amount: nil, pay_to: nil, fee_within: nil, fee_on_top: nil,
      accept: nil, description: nil, external_id: nil, &block)
      sym = name.to_sym
      raise ConfigurationError, "duplicate gate #{sym.inspect}" if @gates.key?(sym)

      defaults = {
        pay_to: PayKit.config.operator.effective_recipient,
        accept: PayKit.config.accept
      }

      gate_obj = if block
        DynamicGate.new(
          name: sym,
          accept: accept || defaults[:accept],
          description: description,
          builder: block,
          defaults: defaults
        )
      else
        Gate.build(
          name: sym,
          amount: amount,
          pay_to: pay_to,
          fee_within: fee_within,
          fee_on_top: fee_on_top,
          accept: accept,
          description: description,
          external_id: external_id,
          default_pay_to: defaults[:pay_to],
          accept_default: defaults[:accept]
        )
      end

      @gates[sym] = gate_obj
    end

    # Coerce arbitrary argument to a Gate (or DynamicGate). Used by
    # the controller helpers so `require_payment! :report`,
    # `require_payment! usd("0.10")`, and `require_payment! gate_obj`
    # all funnel through one resolution path.
    def self.coerce(arg, registry: PayKit.pricing, request: nil, inline_defaults: {})
      case arg
      when Symbol
        raise NoRegistryConfigured if registry.nil?
        registry[arg]
      when Gate, DynamicGate
        arg
      when Price
        Gate.build(
          name: :_inline,
          amount: arg,
          pay_to: inline_defaults[:pay_to] || PayKit.config.operator.effective_recipient,
          accept: inline_defaults[:accept],
          description: inline_defaults[:description],
          external_id: inline_defaults[:external_id],
          default_pay_to: PayKit.config.operator.effective_recipient,
          accept_default: PayKit.config.accept
        )
      else
        raise ConfigurationError, "cannot coerce #{arg.inspect} to a Gate"
      end
    end
  end
end
