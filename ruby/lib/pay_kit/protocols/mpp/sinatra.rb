# frozen_string_literal: true

require_relative "runtime"

module PayKit::Protocols::Mpp
  # Sinatra integration for MPP. Loaded behind a dedicated require so apps
  # that don't use Sinatra don't pay the dependency cost at require time.
  #
  #   class App < Sinatra::Base
  #     helpers PayKit::Protocols::Mpp::Sinatra::Helpers
  #     set :mpp_server, PayKit::Protocols::Mpp.create(method: ..., secret_key: ..., realm: ...)
  #
  #     get "/paid" do
  #       mpp_charge!(amount: "1000", description: "Paid endpoint")
  #       content_type :json
  #       JSON.generate(ok: true)
  #     end
  #   end
  module Sinatra
    module Helpers
      # Gate this route on a valid MPP payment. Halts with a 402 challenge if
      # the request hasn't paid; otherwise sets the receipt/signature headers
      # on the response and returns to let the route render its own body.
      def mpp_charge!(amount:, description: nil, external_id: nil)
        server = settings.mpp_server
        raise Error, "mpp_charge! requires settings.mpp_server" if server.nil?

        result = server.charge(
          request.env["HTTP_AUTHORIZATION"],
          amount: amount,
          description: description,
          external_id: external_id
        )

        case result
        when Challenge
          status, response_headers, body = Server::Decorator.make_challenge_response(result)
          response_headers.each { |name, value| response[name] = value }
          halt status, response.headers, body
        when Settlement
          result.headers.each { |name, value| response[name] = value }
          result
        else
          raise Error, "Unexpected charge result: #{result.class}"
        end
      end
    end
  end
end
