# frozen_string_literal: true

require "json"

module PayKit::Protocols::Mpp
  module Server
    # Helpers for rendering Challenge values as plain Rack responses.
    module Decorator
      # Render a Challenge as a Rack [status, headers, body] triplet.
      # The optional realm argument is accepted for API parity with
      # stripe/mpp-rb but is unused — the realm is already baked into the
      # challenge's WWW-Authenticate header.
      def self.make_challenge_response(challenge, _realm = nil)
        [
          challenge.status,
          challenge.headers.merge(
            "content-type" => "application/json",
            "cache-control" => "no-store"
          ),
          [JSON.generate(challenge.body)]
        ]
      end
    end
  end
end
