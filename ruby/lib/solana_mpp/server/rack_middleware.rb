# frozen_string_literal: true

require "json"

module SolanaMpp
  module Server
    # Rack middleware that protects one route with an MPP charge handler.
    class RackMiddleware
      def initialize(app, handler:, request:, path:)
        @app = app
        @handler = handler
        @request = request
        @path = path
      end

      # Rack entrypoint.
      def call(env)
        return @app.call(env) unless env["PATH_INFO"] == @path

        response = @handler.handle(env[Core::Headers::AUTHORIZATION.upcase.tr("-", "_").prepend("HTTP_")], current_request(env))
        [
          response.status,
          response.headers,
          [JSON.generate(response.body)]
        ]
      end

      private

      def current_request(env)
        @request.respond_to?(:call) ? @request.call(env) : @request
      end
    end
  end
end
