# frozen_string_literal: true

module SolanaMpp
  module Core
    # Parser and formatter for MPP HTTP headers.
    module Headers
      WWW_AUTHENTICATE = "www-authenticate"
      AUTHORIZATION = "authorization"
      PAYMENT_RECEIPT = "payment-receipt"
      PAYMENT_SCHEME = "Payment"

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

      # Parse a single `WWW-Authenticate` challenge.
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

      def strip_payment(header)
        value = header.to_s.strip
        raise ArgumentError, "expected Payment scheme" unless value.downcase.start_with?("payment ")

        value[8..].strip
      end

      def parse_auth_params(input)
        params = {}
        index = 0
        while index < input.length
          index += 1 while index < input.length && [",", " ", "\t"].include?(input[index])
          break if index >= input.length

          key_start = index
          index += 1 while index < input.length && input[index] != "="
          key = input[key_start...index]
          index += 1
          raise ArgumentError, "expected quoted value" unless input[index] == "\""

          index += 1
          value = +""
          while index < input.length
            char = input[index]
            if char == "\\"
              index += 1
              value << input[index].to_s
            elsif char == "\""
              index += 1
              break
            else
              value << char
            end
            index += 1
          end
          params[key] = value
        end
        params
      end

      def escape(value)
        value.to_s.gsub("\\", "\\\\\\").gsub("\"", "\\\"")
      end
    end
  end
end
