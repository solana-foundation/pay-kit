# frozen_string_literal: true

require "pay_core/headers"

module Mpp
  module Core
    # MPP-flavoured `Payment` header parser. Delegates the generic
    # RFC 7235 auth-scheme/auth-param tokenisation to
    # `PayCore::Headers`; only the MPP-specific bits (constructing a
    # `Challenge` / `Receipt` from parsed params, choosing the canonical
    # `Payment` scheme header name set) live in this module.
    module Headers
      WWW_AUTHENTICATE = "www-authenticate"
      AUTHORIZATION = "authorization"
      PAYMENT_RECEIPT = "payment-receipt"
      PAYMENT_SCHEME = ::PayCore::Headers::PAYMENT_SCHEME

      module_function

      # Format a challenge for `WWW-Authenticate`.
      def format_www_authenticate(challenge)
        parts = {
          "id" => challenge.id,
          "realm" => challenge.realm,
          "method" => challenge.method,
          "intent" => challenge.intent,
          "request" => challenge.request,
          "expires" => challenge.expires,
          "digest" => challenge.digest,
          "opaque" => challenge.opaque
        }.compact.map { |key, value| "#{key}=\"#{escape(value)}\"" }
        "Payment #{parts.join(", ")}"
      end

      # Parse all `Payment` challenges across one or more
      # `WWW-Authenticate` values (RFC 7235 sec 4.1). Returns an array of
      # successfully-parsed Challenge objects; malformed individual
      # challenges are skipped. Mirrors the Rust spine which exposes
      # Vec<Result<PaymentChallenge, Error>> and filters at the call site.
      def parse_www_authenticate_all(headers)
        Array(headers).flat_map { |header| split_payment_challenge_values(header) }.filter_map do |chunk|
          parse_www_authenticate(chunk)
        rescue ArgumentError
          nil
        end
      end

      # Generic auth-scheme splitter; delegates to PayCore.
      def split_payment_challenge_values(header)
        ::PayCore::Headers.split_payment_challenge_values(header)
      end

      def token_char?(ch)
        ::PayCore::Headers.token_char?(ch)
      end

      def match_auth_scheme_start(bytes, index)
        ::PayCore::Headers.match_auth_scheme_start(bytes, index)
      end

      # Parse a single `WWW-Authenticate` challenge into a Challenge object.
      def parse_www_authenticate(header)
        params = parse_auth_params(strip_payment(header))
        request = params.fetch("request")
        _decoded_request = Json.parse(Base64Url.decode(request))
        Challenge.new(
          id: params.fetch("id"),
          realm: params.fetch("realm"),
          method: params.fetch("method"),
          intent: params.fetch("intent"),
          request: request,
          expires: params["expires"],
          digest: params["digest"],
          opaque: params["opaque"]
        )
      end

      # Format a receipt for `Payment-Receipt`.
      def format_receipt(receipt)
        Base64Url.encode(Json.canonical_generate(receipt.to_h))
      end

      # Parse a `Payment-Receipt` value.
      def parse_receipt(header)
        value = Json.parse(Base64Url.decode(header))
        Receipt.new(
          status: value.fetch("status"),
          method: value.fetch("method"),
          reference: value.fetch("reference"),
          challenge_id: value.fetch("challengeId"),
          external_id: value["externalId"],
          timestamp: value["timestamp"]
        )
      end

      # Strip the leading "Payment " scheme tag from a header value.
      def strip_payment(header)
        ::PayCore::Headers.strip_payment(header)
      end

      # Parse RFC 7235 sec 2.1 auth-params; accepts quoted-string and
      # token form. Delegates to PayCore::Headers.
      def parse_auth_params(input)
        ::PayCore::Headers.parse_auth_params(input)
      end

      def escape(value)
        ::PayCore::Headers.escape(value)
      end
    end
  end
end
