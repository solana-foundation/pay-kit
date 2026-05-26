# frozen_string_literal: true

require "base64"
require "json"

require "mpp/methods/solana/mints"

module X402
  module Interop
    module Client
      module_function

      # CAIP-2 indexed view of the canonical stablecoin mint table from the
      # shared core (`Mpp::Methods::Solana::Mints::MINTS`). The shared table
      # is keyed by Solana network name (`devnet` / `mainnet`); x402 wire
      # network IDs use CAIP-2 form, so we project the devnet entries into
      # the CAIP-2 namespace here rather than redeclaring mint addresses.
      SOLANA_DEVNET_CAIP2 = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
      STABLECOIN_MINTS = {
        "USDC" => {
          SOLANA_DEVNET_CAIP2 => ::Mpp::Methods::Solana::Mints::MINTS.fetch("USDC").fetch("devnet")
        },
        "PYUSD" => {
          SOLANA_DEVNET_CAIP2 => ::Mpp::Methods::Solana::Mints::MINTS.fetch("PYUSD").fetch("devnet")
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
          selected_requirement?(requirement, network, scheme)
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
        # Accept both canonical Rust-spine `amount` and the TS reference
        # fixture's `maxAmountRequired`. Rust deserializes either field at
        # rust/crates/x402/src/protocol/schemes/exact/types.rs:337-339, so
        # we match that tolerance to stay interop-compatible with the TS
        # exact server.
        amount_value = requirement["amount"] || requirement["maxAmountRequired"]
        requirement["scheme"] == scheme &&
          requirement["network"] == network &&
          requirement["asset"].is_a?(String) &&
          amount_value.is_a?(String)
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
        # Rust spine carries top-level `resource` as a typed `ResourceInfo`
        # object (rust/crates/x402/src/protocol/schemes/exact/types.rs:491)
        # but the TS reference fixture emits it as a bare URL string
        # (harness/src/fixtures/typescript/exact-server.ts:85). Tolerate
        # both shapes so the Ruby client can interoperate with either
        # server fixture; normalise the string form into the canonical
        # `{ url: <string> }` hash downstream consumers expect.
        case resource
        when Hash then resource
        when String then resource.empty? ? nil : {"url" => resource}
        end
      end

      def header_value(headers, name)
        match = headers.find { |key, _value| key.casecmp(name).zero? }
        match&.last
      end
    end
  end
end
