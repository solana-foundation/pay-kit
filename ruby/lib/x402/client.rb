# frozen_string_literal: true

require "base64"
require "json"

module X402
  module Interop
    module Client
      module_function

      STABLECOIN_MINTS = {
        "USDC" => {
          "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
        },
        "PYUSD" => {
          "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" => "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
        }
      }.freeze

      def select_svm_requirement(headers:, body:, network:, scheme: "exact", preferred_currencies: [])
        requirement, = select_svm_challenge(
          headers: headers,
          body: body,
          network: network,
          scheme: scheme,
          preferred_currencies: preferred_currencies
        )
        requirement
      end

      def select_svm_challenge(headers:, body:, network:, scheme: "exact", preferred_currencies: [])
        accepts = []
        header_envelope = load_payment_required_header(headers)
        body_envelope = load_payment_required_body(body)
        accepts.concat(accepts_from_envelope(header_envelope).map { |entry| [entry, resource_from_envelope(header_envelope)] })
        accepts.concat(accepts_from_envelope(body_envelope).map { |entry| [entry, resource_from_envelope(body_envelope)] })

        selected = accepts.find do |requirement, _resource|
          requirement["scheme"] == scheme &&
            requirement["network"] == network &&
            requirement["asset"].is_a?(String) &&
            requirement["amount"].is_a?(String)
        end
        return [nil, nil] unless selected

        if preferred_currencies.any?
          preferred_currencies.each do |currency|
            preferred = accepts.find do |requirement, _resource|
              selected_requirement?(requirement, network, scheme) &&
                matches_currency?(requirement, currency, network)
            end
            return preferred if preferred
          end
        end

        selected
      end

      def selected_requirement?(requirement, network, scheme)
        requirement["scheme"] == scheme &&
          requirement["network"] == network &&
          requirement["asset"].is_a?(String) &&
          requirement["amount"].is_a?(String)
      end

      def matches_currency?(requirement, currency, network)
        normalized = currency.to_s.upcase
        mint = STABLECOIN_MINTS.dig(normalized, network) || currency
        requirement["currency"] == currency ||
          requirement["currency"] == normalized ||
          requirement["asset"] == mint
      end

      def load_payment_required_header(headers)
        encoded = header_value(headers, "PAYMENT-REQUIRED")
        return nil if encoded.nil? || encoded.empty?

        JSON.parse(Base64.strict_decode64(encoded))
      rescue ArgumentError, JSON::ParserError
        nil
      end

      def load_payment_required_body(body)
        return nil if body.nil? || body.empty?

        JSON.parse(body)
      rescue JSON::ParserError
        nil
      end

      def accepts_from_envelope(envelope)
        return [] unless envelope.is_a?(Hash)

        accepts = envelope["accepts"]
        return [] unless accepts.is_a?(Array)

        accepts.select { |entry| entry.is_a?(Hash) }
      end

      def resource_from_envelope(envelope)
        return nil unless envelope.is_a?(Hash)

        resource = envelope["resource"]
        resource if resource.is_a?(Hash)
      end

      def header_value(headers, name)
        match = headers.find { |key, _value| key.casecmp(name).zero? }
        match&.last
      end
    end
  end
end
