# frozen_string_literal: true

module Mpp
  module Intent
    # MPP charge request wire object.
    class ChargeRequest
      attr_reader :amount, :currency, :recipient, :description, :external_id, :method_details

      def initialize(amount:, currency:, recipient: nil, description: nil, external_id: nil, method_details: nil)
        raise ArgumentError, "amount must be a positive base-unit integer string" unless amount.to_s.match?(/\A[1-9][0-9]*\z/)
        raise ArgumentError, "currency is required" if currency.to_s.empty?
        raise ArgumentError, "methodDetails must be a Hash" unless method_details.nil? || method_details.is_a?(Hash)

        @amount = amount.to_s
        @currency = currency.to_s
        @recipient = recipient
        @description = description
        @external_id = external_id
        @method_details = method_details || {}
      end

      # Build a charge request from decoded wire JSON.
      def self.from_h(value)
        raise ArgumentError, "charge request must be an object" unless value.is_a?(Hash)

        new(
          amount: value.fetch("amount"),
          currency: value.fetch("currency"),
          recipient: value["recipient"],
          description: value["description"],
          external_id: value["externalId"],
          method_details: value["methodDetails"]
        )
      end

      # Convert a display amount to base units.
      def self.parse_units(amount, decimals)
        raw = amount.to_s
        raise ArgumentError, "invalid amount" unless raw.match?(/\A[0-9]+(\.[0-9]+)?\z/)

        whole, frac = raw.split(".", 2)
        frac ||= ""
        raise ArgumentError, "too many decimal places" if frac.length > decimals

        (whole + frac.ljust(decimals, "0")).sub(/\A0+(?=\d)/, "")
      end

      # Serialize to the camelCase wire object.
      def to_h
        {
          "amount" => amount,
          "currency" => currency,
          "recipient" => recipient,
          "description" => description,
          "externalId" => external_id,
          "methodDetails" => method_details.empty? ? nil : method_details
        }.compact
      end

      # Parse the base-unit amount as an Integer.
      def amount_i
        Integer(amount, 10)
      rescue ArgumentError
        raise ArgumentError, "invalid amount: #{amount}"
      end
    end
  end
end
