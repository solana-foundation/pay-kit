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
      #
      # Detects RFC 7235 sec 2.1 auth-scheme boundaries (a token followed by whitespace and a
      # key=value pair), not just literal "Payment" occurrences. This is required to correctly
      # terminate a Payment chunk when a different scheme (e.g. Bearer) follows it on the same
      # header value, and to skip over non-Payment schemes that precede or interleave with
      # Payment schemes.
      def split_payment_challenge_values(header)
        bytes = header.to_s
        scheme_starts = [] # array of [offset, is_payment]
        in_quote = false
        escaped = false
        at_boundary = true
        i = 0
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
            at_boundary = false
            i += 1
            next
          end

          if ch == ","
            at_boundary = true
            i += 1
            next
          end

          if [" ", "\t"].include?(ch)
            i += 1
            next
          end

          if at_boundary && token_char?(ch)
            match = match_auth_scheme_start(bytes, i)
            if match
              scheme_end, is_payment = match
              scheme_starts << [i, is_payment]
              i = scheme_end
              at_boundary = false
              next
            end
          end

          at_boundary = false
          i += 1
        end

        return [] if scheme_starts.empty?

        chunks = []
        scheme_starts.each_with_index do |(start, is_payment), idx|
          next unless is_payment

          finish = scheme_starts[idx + 1] ? scheme_starts[idx + 1][0] : bytes.length
          chunk = bytes[start...finish].strip.sub(/,\s*\z/, "").strip
          chunks << chunk unless chunk.empty?
        end
        chunks
      end

      # RFC 7230 sec 3.2.6 tchar.
      TCHAR_EXTRA = "!#$%&'*+-.^_`|~"
      def token_char?(ch)
        return false unless ch

        ch.match?(/[A-Za-z0-9]/) || TCHAR_EXTRA.include?(ch)
      end

      # If `bytes[index]` starts an auth-scheme (RFC 7235 sec 2.1), return
      # [offset_after_scheme, is_payment_scheme]. Otherwise return nil.
      #
      # A scheme requires: token, 1*SP, then non-empty content (either an
      # auth-param list `key=val,...` or a token68 credential). A bare
      # `token=` (no SP gap) is an auth-param continuation, not a new scheme.
      def match_auth_scheme_start(bytes, index)
        token_end = index
        token_end += 1 while token_end < bytes.length && token_char?(bytes[token_end])
        return nil if token_end == index

        return nil unless [" ", "\t"].include?(bytes[token_end])

        cursor = token_end
        cursor += 1 while cursor < bytes.length && [" ", "\t"].include?(bytes[cursor])
        return nil if cursor >= bytes.length || bytes[cursor] == ","

        scheme = bytes[index, token_end - index]
        [token_end, scheme.casecmp(PAYMENT_SCHEME).zero?]
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
