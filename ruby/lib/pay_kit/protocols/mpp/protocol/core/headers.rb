# frozen_string_literal: true

require "pay_core/headers"
require "pay_core/rfc3339_parser"

module PayKit::Protocols::Mpp
  module Protocol
    module Core
      # MPP-flavoured `Payment` header formatter and parser. Delegates the
      # generic RFC 7235 auth-scheme/auth-param tokenisation to
      # `PayCore::Headers`; the MPP-specific bits (constructing a
      # `PayKit::Protocols::Mpp::Protocol::Core::Challenge` / `PayKit::Protocols::Mpp::Protocol::Core::Receipt` from parsed params and
      # the canonical `Payment` scheme header constants) live here.
      module Headers
        WWW_AUTHENTICATE = "www-authenticate"
        AUTHORIZATION = "authorization"
        PAYMENT_RECEIPT = "payment-receipt"
        PAYMENT_SCHEME = ::PayCore::Headers::PAYMENT_SCHEME

        # Cap on any base64url token this parser decodes, enforced BEFORE
        # `Base64Url.decode` + JSON parse so an oversized attacker-controlled
        # header value cannot drive unbounded decode/parse work. Matches
        # `Credential::MAX_TOKEN_LENGTH` and the 16 KiB `MAX_TOKEN_LEN` caps
        # in the Rust/Python/PHP/Go/Lua MPP header parsers.
        MAX_TOKEN_LENGTH = 16 * 1024

        module_function

        # Format a challenge for `WWW-Authenticate`.
        def format_www_authenticate(challenge)
          parts = {
            "id" => challenge.id,
            "realm" => challenge.realm,
            "method" => challenge.method,
            "intent" => challenge.intent,
            "request" => challenge.request,
            "description" => challenge.description,
            "expires" => challenge.expires,
            "digest" => challenge.digest,
            "opaque" => challenge.opaque
          }.compact.map { |key, value| "#{key}=\"#{::PayCore::Headers.escape(value)}\"" }
          "Payment #{parts.join(", ")}"
        end

        # Parse all `Payment` challenges across one or more `WWW-Authenticate`
        # values (RFC 7235 sec 4.1). Returns an array of successfully-parsed
        # Challenge objects; malformed individual challenges are skipped.
        def parse_www_authenticate_all(headers)
          Array(headers).flat_map { |header| ::PayCore::Headers.split_payment_challenge_values(header) }.filter_map do |chunk|
            parse_www_authenticate(chunk)
          rescue ArgumentError
            nil
          end
        end

        # Generic RFC 7235 sec 2.1 auth-params parser; delegates to PayCore.
        def parse_auth_params(input)
          ::PayCore::Headers.parse_auth_params(input)
        end

        # Parse a single `WWW-Authenticate` challenge into a Challenge object.
        def parse_www_authenticate(header)
          params = ::PayCore::Headers.parse_auth_params(::PayCore::Headers.strip_payment(header))
          request = params.fetch("request")
          if request.bytesize > MAX_TOKEN_LENGTH
            raise ArgumentError, "Challenge request parameter exceeds maximum length of #{MAX_TOKEN_LENGTH} bytes"
          end

          _decoded_request = ::PayCore::Json.parse(::PayCore::Base64Url.decode(request))
          Core::Challenge.new(
            id: params.fetch("id"),
            realm: params.fetch("realm"),
            method: params.fetch("method"),
            intent: params.fetch("intent"),
            request: request,
            expires: params["expires"],
            description: params["description"],
            digest: params["digest"],
            opaque: params["opaque"]
          )
        end

        # Format a receipt for `Payment-Receipt`.
        def format_receipt(receipt)
          ::PayCore::Base64Url.encode(::PayCore::Json.canonical_generate(receipt.to_h))
        end

        # Parse a `Payment-Receipt` value. The canonical receipt shape
        # (mpp-tools) requires `status`, `method`, `reference`, and `timestamp`
        # and validates that the timestamp is ISO-8601 / RFC 3339. `challengeId`
        # is advisory and not part of the canonical receipt shape, so it is
        # accepted when present but never required.
        def parse_receipt(header)
          if header.bytesize > MAX_TOKEN_LENGTH
            raise ArgumentError, "Receipt exceeds maximum length of #{MAX_TOKEN_LENGTH} bytes"
          end

          value = ::PayCore::Json.parse(::PayCore::Base64Url.decode(header))
          timestamp = value.fetch("timestamp")
          raise ArgumentError, "receipt timestamp must be ISO-8601" if ::PayCore::Rfc3339Parser.parse(timestamp).nil?

          Core::Receipt.new(
            status: value.fetch("status"),
            method: value.fetch("method"),
            reference: value.fetch("reference"),
            challenge_id: value["challengeId"],
            external_id: value["externalId"],
            timestamp: timestamp
          )
        end
      end
    end
  end
end
