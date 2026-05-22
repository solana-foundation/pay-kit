# frozen_string_literal: true

module Mpp
  module Server
    # Rack middleware for MPP-protected routes.
    #
    # Routes opt into payment by setting `env["mpp.charge"]` to a hash with
    # :amount and :description (and optional :external_id) before returning.
    # The middleware then either replaces the response with a 402 challenge
    # (if no valid Payment authorization was supplied) or settles on-chain
    # and injects the receipt + signature headers into the route's response.
    #
    #   use Mpp::Server::Middleware, handler: Mpp.create(...)
    #
    #   get "/paid" do
    #     env["mpp.charge"] = { amount: "1000", description: "Paid endpoint" }
    #     json ok: true
    #   end
    #
    # Note: the route runs before the middleware decides whether to gate. For
    # expensive routes, prefer the Sinatra helper Mpp::Sinatra::Helpers, which
    # halts early.
    class Middleware
      def initialize(app, handler:)
        @app = app
        @handler = handler
      end

      def call(env)
        authorization = env["HTTP_AUTHORIZATION"]
        status, headers, body = @app.call(env)

        charge = env["mpp.charge"]
        return [status, headers, body] unless charge

        params = normalize_params(charge)
        result = @handler.charge(authorization, **params)

        case result
        when Challenge
          Decorator.make_challenge_response(result)
        when Settlement
          [status, headers.merge(result.headers), body]
        else
          raise Error, "Unexpected handler result: #{result.class}"
        end
      end

      private

      def normalize_params(charge)
        charge.each_with_object({}) { |(key, value), out| out[key.to_sym] = value }
      end
    end
  end
end
