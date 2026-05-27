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

      proof = begin
        dispatcher.verify(gate, request)
      rescue ::PayKit::InvalidProof => e
        halt_with_payment_response(::PayKit::Rack::PaymentRequired.render_invalid(e))
      end
      if proof
        request.env[::PayKit::Rack::PaymentRequired::ENV_PAYMENT_KEY] = proof
        return proof
      end

      challenge = dispatcher.challenge_for(gate, request)
      halt_with_payment_response(::PayKit::Rack::PaymentRequired.render_402(challenge))
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

    # 402 responses go through Sinatra's `halt` rather than `raise` so
    # the exception never bubbles up to Sinatra's `handle_exception!`,
    # which otherwise misclassifies non-Sinatra::Error exceptions as
    # 500s and fires `dump_errors!` (a noisy backtrace per gated
    # request). The Rack middleware retains its own
    # `rescue PayKit::PaymentRequired` for non-Sinatra mounts and any
    # path that raises outside a route handler.
    def halt_with_payment_response(rack_tuple)
      status, headers, body = rack_tuple
      headers.each { |name, value| response.headers[name] = value }
      halt(status, body.first)
    end

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
