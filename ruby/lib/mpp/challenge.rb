# frozen_string_literal: true

module Mpp
  # Returned by Server#charge when no valid payment was supplied. Render this
  # as HTTP 402 to the client. Use Mpp::Server::Decorator.make_challenge_response
  # if you don't want to assemble the response yourself.
  class Challenge
    STATUS = 402

    attr_reader :www_authenticate, :body, :reason

    def initialize(www_authenticate:, body:, reason: nil)
      @www_authenticate = www_authenticate
      @body = body
      @reason = reason
    end

    def status
      STATUS
    end

    def headers
      {Core::Headers::WWW_AUTHENTICATE => www_authenticate}
    end
  end
end
