# frozen_string_literal: true

require "pay_core/base64_url"
require "pay_core/json"

module Mpp
  module Protocol
    module Core
      # Payment credential carried by the `Authorization` header.
      class Credential
        MAX_TOKEN_LENGTH = 16 * 1024

        attr_reader :challenge, :payload, :source

        def initialize(challenge:, payload:, source: nil)
          raise ArgumentError, "payload must be an object" unless payload.is_a?(Hash)

          @challenge = challenge
          @payload = payload
          @source = source
        end

        # Serialize to the wire credential shape.
        def to_h
          value = {
            "challenge" => challenge.to_h,
            "payload" => payload
          }
          value["source"] = source unless source.nil?
          value
        end

        # Format as `Authorization: Payment ...` value.
        def to_authorization_header
          "Payment #{::PayCore::Base64Url.encode(::PayCore::Json.canonical_generate(to_h))}"
        end

        # Parse an `Authorization` header value.
        def self.from_authorization_header(header)
          token = extract_payment_token(header)
          raise ArgumentError, "expected Payment scheme" if token.nil?
          raise ArgumentError, "token exceeds maximum length" if token.bytesize > MAX_TOKEN_LENGTH

          decoded = ::PayCore::Json.parse(::PayCore::Base64Url.decode(token))
          new(
            challenge: ChallengeEcho.from_h(decoded.fetch("challenge")),
            payload: decoded.fetch("payload"),
            source: decoded["source"]
          )
        end

        def self.extract_payment_token(header)
          header.to_s.split(",").map(&:strip).find { |part| part.downcase.start_with?("payment ") }&.[](8..)&.strip
        end
      end
    end
  end
end
