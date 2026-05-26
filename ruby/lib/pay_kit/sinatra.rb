# frozen_string_literal: true

require_relative "errors"
require_relative "rack/payment_required"

module PayKit
  # Sinatra helpers. Opt-in: require explicitly from your app file.
  #
  #   require "solana_pay_kit"
  #   require "solana_pay_kit/sinatra"
  #
  #   class App < Sinatra::Base
  #     helpers PayKit::Sinatra
  #     use PayKit::Rack::PaymentRequired
  #
  #     get "/report" do
  #       require_payment! :report
  #       json ok: true, paid_by: payment.protocol
  #     end
  #   end
  #
  # Three primitives, mirroring Clearance's surface:
  #
  #   require_payment! arg, **opts   bang form, halts with 402 if unpaid
  #   paid? arg                      predicate, never halts
  #   payment                        accessor, nil until paid
  module Sinatra
    include Helpers::Pricing

    def require_payment!(arg, **inline_opts)
      gate = resolve_gate(arg, inline_opts)
      request.env[::PayKit::Rack::PaymentRequired::ENV_EXPECTED_GATE_KEY] = gate

      proof = dispatcher.verify(gate, request)
      if proof
        request.env[::PayKit::Rack::PaymentRequired::ENV_PAYMENT_KEY] = proof
        return proof
      end

      challenge = dispatcher.challenge_for(gate, request)
      raise ::PayKit::PaymentRequired.new(challenge)
    end

    def paid?(arg, **inline_opts)
      gate = resolve_gate(arg, inline_opts)
      proof = dispatcher.verify(gate, request)
      if proof
        request.env[::PayKit::Rack::PaymentRequired::ENV_PAYMENT_KEY] = proof
        true
      else
        false
      end
    rescue ::PayKit::InvalidProof
      false
    end

    def payment
      request.env[::PayKit::Rack::PaymentRequired::ENV_PAYMENT_KEY]
    end

    private

    def dispatcher
      request.env[::PayKit::Rack::PaymentRequired::ENV_DISPATCHER_KEY] ||
        raise(::PayKit::ConfigurationError, "PayKit::Rack::PaymentRequired middleware not mounted")
    end

    def resolve_gate(arg, inline_opts)
      registry = sinatra_pricing
      gate = ::PayKit::Pricing.coerce(arg, registry: registry, request: request, inline_defaults: inline_opts)
      gate.is_a?(::PayKit::DynamicGate) ? gate.resolve(request) : gate
    end

    def sinatra_pricing
      if respond_to?(:settings) && settings.respond_to?(:pricing) && settings.pricing
        settings.pricing
      else
        ::PayKit.pricing
      end
    end
  end
end
