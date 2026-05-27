# frozen_string_literal: true

require_relative "errors"
require_relative "signer"

module PayKit
  # Merchant identity bundle: where settled funds land (`recipient`),
  # who signs (`signer`), and whether the signer also pays the on-chain
  # network fees (`fee_payer`). Created via the `c.operator do |op| ... end`
  # block inside `PayKit.configure`, or assigned directly with
  # `c.operator = PayKit::Operator.new(...)`.
  #
  # Setters follow a deliberate "nil-as-no-op" convention so env-driven
  # configuration stays free of `if ENV[...]` guards: when the right-hand
  # side is `nil` the assignment is silently dropped and the existing
  # value (typically a default) survives. The escape hatch for actually
  # clearing a previously-set value is `op.reset!(:field)`.
  #
  # The default operator is the demo signer with `fee_payer: true` and
  # `recipient: nil`. `recipient` resolves to `signer.pubkey` via
  # `effective_recipient`, so a zero-config boot still has a settlement
  # destination. `PayKit::Config` enforces the mainnet refusal rule on
  # top of this object (see `PayKit::DemoSignerOnMainnetError`).
  class Operator
    DEFAULT_FEE_PAYER = true

    def initialize(recipient: nil, signer: nil, fee_payer: nil)
      @recipient = nil
      @signer = ::PayKit::Signer.demo
      @fee_payer = DEFAULT_FEE_PAYER

      assign_recipient(recipient)
      assign_signer(signer)
      assign_fee_payer(fee_payer)

      yield self if block_given?
    end

    attr_reader :recipient, :signer, :fee_payer

    # Nil-as-no-op setter. Non-nil values must be Strings.
    def recipient=(value)
      assign_recipient(value)
    end

    # Nil-as-no-op setter. Non-nil values must respond to the signer
    # duck-type (`#pubkey`, `#sign(message)`, `#fee_payer?`).
    def signer=(value)
      assign_signer(value)
    end

    # Nil-as-no-op setter. Non-nil values must be exactly `true` or
    # `false`; truthy coercion would mask configuration bugs.
    def fee_payer=(value)
      assign_fee_payer(value)
    end

    # `true` when the operator's signer should co-sign as Solana fee
    # payer on settlement transactions. Mirrors the boolean accessor
    # but reads predicate-style at call sites.
    def fee_payer?
      @fee_payer == true
    end

    # The address that should receive funds when a gate omits a
    # per-route `pay_to:`. Returns the explicit `recipient` when set,
    # otherwise the signer's own pubkey.
    def effective_recipient
      @recipient || @signer.pubkey
    end

    # Restore a single field to its construction default. `:recipient`
    # → nil, `:signer` → `Signer.demo`, `:fee_payer` → true. Use this
    # when the env-driven nil-no-op pattern is not enough.
    def reset!(field)
      case field
      when :recipient then @recipient = nil
      when :signer then @signer = ::PayKit::Signer.demo
      when :fee_payer then @fee_payer = DEFAULT_FEE_PAYER
      else
        raise ArgumentError, "unknown operator field #{field.inspect}; expected :recipient, :signer, or :fee_payer"
      end
      self
    end

    # Two operators are equal when their resolved recipient, signer
    # public key, and fee-payer flag all match. Used by tests and by
    # the dispatcher when it needs to detect a config change.
    def ==(other)
      other.is_a?(Operator) &&
        effective_recipient == other.effective_recipient &&
        signer.pubkey == other.signer.pubkey &&
        fee_payer? == other.fee_payer?
    end
    alias_method :eql?, :==

    def hash
      [Operator, effective_recipient, signer.pubkey, fee_payer?].hash
    end

    def to_h
      {
        recipient: effective_recipient,
        signer_pubkey: @signer.pubkey,
        signer_class: @signer.class.name,
        fee_payer: @fee_payer
      }
    end

    private

    def assign_recipient(value)
      return if value.nil?
      unless value.is_a?(String)
        raise ::PayKit::ConfigurationError, "operator.recipient must be a String, got #{value.class.name}"
      end

      @recipient = value
    end

    def assign_signer(value)
      return if value.nil?
      unless signer_like?(value)
        raise ::PayKit::ConfigurationError,
          "operator.signer must respond to #pubkey, #sign, and #fee_payer? — got #{value.class.name}"
      end

      @signer = value
    end

    def assign_fee_payer(value)
      return if value.nil?
      unless value == true || value == false
        raise ::PayKit::ConfigurationError,
          "operator.fee_payer must be true or false, got #{value.inspect}"
      end

      @fee_payer = value
    end

    def signer_like?(value)
      value.respond_to?(:pubkey) && value.respond_to?(:sign) && value.respond_to?(:fee_payer?)
    end
  end
end
