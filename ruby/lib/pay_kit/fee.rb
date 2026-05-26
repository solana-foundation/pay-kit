# frozen_string_literal: true

require_relative "errors"
require_relative "price"

module PayKit
  # Single fee entry: a recipient address and what they receive.
  Fee = Data.define(:recipient, :price, :kind) do
    # Whether this fee is taken out of the gate's amount (`:within`)
    # or added on top of it (`:on_top`).
    def within?
      kind == :within
    end

    def on_top?
      kind == :on_top
    end
  end

  # Build Fee arrays from the `{ recipient => Price }` hash kwargs
  # accepted by `gate(...)`. Coerces user input and validates the
  # shape before the Gate sees it.
  module FeeBuilder
    module_function

    def from_hash(hash, kind:)
      return [].freeze if hash.nil?

      unless hash.is_a?(Hash)
        raise ConfigurationError, "fee_#{kind} must be a Hash of { recipient => price }"
      end

      hash.map do |recipient, price|
        unless recipient.is_a?(String) && !recipient.empty?
          raise ConfigurationError, "fee_#{kind} recipient must be a non-empty String, got #{recipient.inspect}"
        end
        unless price.is_a?(Price)
          raise ConfigurationError, "fee_#{kind} price for #{recipient.inspect} must be built via usd(...)/eur(...)"
        end

        Fee.new(recipient: recipient, price: price, kind: kind)
      end.freeze
    end
  end
end
