# frozen_string_literal: true

require_relative "../errors"
require_relative "../challenge"
require_relative "../../x402/server/exact"

module PayKit
  module Protocols
    # x402 adapter. Wraps `::X402::Server::Exact` for verification and
    # settlement; produces `accepts[]` entries from `Gate` instances.
    #
    # The class-level `.exact` callable returns a frozen `ProtocolRef`
    # so gates can name the scheme explicitly:
    #
    #   accept: PayKit::Protocols::X402.exact   # equivalent to accept: :x402
    class X402
      EXACT_REF = ProtocolRef.new(protocol: :x402, scheme: :exact).freeze
      def self.exact = EXACT_REF

      # x402 cannot route multi-recipient settlement, so gates with
      # fees auto-disable x402 at Gate.build time. The adapter still
      # asserts at request time as a defense in depth.
      def initialize(config:, exact_config_for:)
        @config = config
        @exact_config_for = exact_config_for
        freeze
      end

      def detect?(request)
        header_value(request, ::X402::Constants::PAYMENT_SIGNATURE_HEADER) ||
          header_value(request, "X-PAYMENT") # v1 legacy
      end

      def accepts_entry(gate, request)
        ensure_no_fees!(gate)
        exact_config = build_exact_config(gate, request)
        ::X402::Server::Exact.exact_requirements(exact_config, resource: request.path).first.tap do |entry|
          entry[:protocol] = "x402"
        end
      end

      def challenge_headers(gate, request)
        ensure_no_fees!(gate)
        exact_config = build_exact_config(gate, request)
        challenge = ::X402::Server::Exact.exact_challenge(exact_config, resource: request.path)
        {
          ::X402::Constants::PAYMENT_REQUIRED_HEADER =>
            ::X402::Server::Exact.encode_payment_required(challenge)
        }
      end

      def verify_and_settle(gate, request)
        ensure_no_fees!(gate)
        exact_config = build_exact_config(gate, request)
        payment_header = detect?(request)
        signature = ::X402::Server::Exact.settle_exact_payment(
          exact_config,
          payment_header,
          resource: request.path
        )

        payment_response = ::JSON.generate(
          success: true,
          network: exact_config.network,
          transaction: signature
        )

        Payment.new(
          protocol: :x402,
          scheme: :exact,
          transaction: signature,
          settlement_headers: {
            ::X402::Constants::PAYMENT_RESPONSE_HEADER => payment_response,
            exact_config.settlement_header => signature
          },
          raw: payment_header
        )
      rescue ::X402::Error => e
        raise InvalidProof.new(:payment_invalid, e.message)
      rescue => e
        raise InvalidProof.new(:payment_invalid, e.message)
      end

      private

      def header_value(request, name)
        rack_key = "HTTP_" + name.upcase.tr("-", "_")
        request.env[rack_key] || request.env[name]
      end

      def build_exact_config(gate, request)
        # `exact_config_for` is provided at boot by PayKit::Rack::PaymentRequired
        # so we don't re-resolve env vars per request. Caller-supplied
        # to keep this adapter Rack-only.
        @exact_config_for.call(gate, request)
      end

      def ensure_no_fees!(gate)
        return unless gate.fees?

        raise ConfigurationError,
          "gate #{gate.name.inspect}: x402 cannot settle multi-recipient fees - this gate should have x402 auto-disabled"
      end
    end
  end
end
