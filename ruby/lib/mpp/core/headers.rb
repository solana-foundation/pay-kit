# frozen_string_literal: true

module Mpp
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

      # Parse all `Payment` challenges across one or more `WWW-Authenticate` values (RFC 7235 sec 4.1).
      # Returns an array of successfully-parsed Challenge objects; malformed individual challenges are skipped.
      # Mirrors the Rust spine which exposes Vec<Result<PaymentChallenge, Error>> and filters at the call site.
      def parse_www_authenticate_all(headers)
        Array(headers).flat_map { |header| split_payment_challenge_values(header) }.filter_map do |chunk|
          parse_www_authenticate(chunk)
        rescue ArgumentError
          nil
        end
      end

      # Split a WWW-Authenticate header value into individual Payment challenges (quote-aware).
      def split_payment_challenge_values(header)
        bytes = header.to_s
        starts = []
        in_quote = false
        escaped = false
        i = 0
        scheme = PAYMENT_SCHEME
        slen = scheme.length
        while i < bytes.length
          ch = bytes[i]
          if in_quote
            if escaped
              escaped = false
            elsif ch == "\\"
              escaped = true
            elsif ch == "\""
              in_quote = false
            end
            i += 1
            next
          end

          if ch == "\""
            in_quote = true
            i += 1
            next
          end

          if payment_scheme_start?(bytes, i, scheme, slen)
            starts << i
            i += slen
            next
          end

          i += 1
        end

        return [] if starts.empty?

        starts.each_with_index.map do |start, idx|
          finish = starts[idx + 1] || bytes.length
          bytes[start...finish].strip.sub(/,\s*\z/, "").strip
        end.reject(&:empty?)
      end

      def payment_scheme_start?(bytes, index, scheme, slen)
        return false if index + slen >= bytes.length

        prefix = bytes[index, slen]
        return false unless prefix&.casecmp(scheme)&.zero?

        next_char = bytes[index + slen]
        return false unless next_char && [" ", "\t"].include?(next_char)

        prev = index - 1
        prev -= 1 while prev >= 0 && [" ", "\t"].include?(bytes[prev])
        prev < 0 || bytes[prev] == ","
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
        scheme_len = PAYMENT_SCHEME.length
        unless value.length > scheme_len && value[0, scheme_len].casecmp(PAYMENT_SCHEME).zero? && [" ", "\t"].include?(value[scheme_len])
          raise ArgumentError, "expected Payment scheme"
        end

        value[(scheme_len + 1)..].strip
      end

      # Parse RFC 7235 sec 2.1 auth-params; accepts quoted-string and token form.
      def parse_auth_params(input)
        params = {}
        index = 0
        while index < input.length
          index += 1 while index < input.length && [",", " ", "\t"].include?(input[index])
          break if index >= input.length

          key_start = index
          index += 1 while index < input.length && input[index] != "=" && input[index] != "," && input[index] != " " && input[index] != "\t"
          key = input[key_start...index]
          index += 1 while index < input.length && [" ", "\t"].include?(input[index])
          raise ArgumentError, "invalid auth parameter" if key.empty? || index >= input.length || input[index] != "="

          index += 1
          index += 1 while index < input.length && [" ", "\t"].include?(input[index])

          value = if index < input.length && input[index] == "\""
            index += 1
            buf = +""
            while index < input.length
              char = input[index]
              if char == "\\"
                index += 1
                buf << input[index].to_s
              elsif char == "\""
                index += 1
                break
              else
                buf << char
              end
              index += 1
            end
            buf
          else
            value_start = index
            index += 1 while index < input.length && input[index] != ","
            input[value_start...index].rstrip
          end

          raise ArgumentError, "duplicate parameter: #{key}" if params.key?(key)
          params[key] = value
        end
        params
      end

      def escape(value)
        # RFC 9110 section 5.5 forbids CR and LF in header field values.
        # Silent strip would let malformed inputs round-trip and would let a
        # caller-controlled realm inject extra HTTP headers. Reject with an
        # explicit error so the problem surfaces at emission time.
        string = value.to_s
        raise ArgumentError, "control character in header parameter value" if string.match?(/[\r\n]/)
        string.gsub("\\", "\\\\\\").gsub("\"", "\\\"")
      end
    end
  end
end
