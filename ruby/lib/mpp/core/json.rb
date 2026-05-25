# frozen_string_literal: true

require "json"

module Mpp
  module Core
    # RFC 8785 canonical JSON encoder for MPP header payloads.
    #
    # Vendors a small JCS implementation rather than delegating to JSON.generate so the
    # ordering, number serialization, and surrogate validation rules match the Rust spine.
    # See RFC 8785 sec 3.2.2 and sec 3.2.3.
    #
    # @see https://datatracker.ietf.org/doc/html/rfc8785 RFC 8785 JSON Canonicalization Scheme
    # @see https://tc39.es/ecma262/multipage/abstract-operations.html#sec-numeric-types-number-tostring
    #      ECMA-262 Number::toString algorithm
    module Json
      module_function

      # Encode a Ruby object with stable object key ordering (UTF-16 code-unit).
      def canonical_generate(value)
        encode_value(value)
      end

      # Decode JSON and preserve object keys as strings.
      def parse(value)
        JSON.parse(value)
      rescue JSON::ParserError => error
        raise ArgumentError, "invalid JSON: #{error.message}"
      end

      # ── private encoders ──

      class << self
        private

        def encode_value(value)
          case value
          when Hash then encode_object(value)
          when Array then "[" + value.map { |item| encode_value(item) }.join(",") + "]"
          when String then encode_string(value)
          when Integer then value.to_s
          when Float then encode_number(value)
          when true then "true"
          when false then "false"
          when nil then "null"
          else
            raise ArgumentError, "unsupported JSON value #{value.class}"
          end
        end

        def encode_object(hash)
          string_keys = hash.each_with_object({}) do |(key, val), memo|
            string_key = key.is_a?(Symbol) ? key.to_s : key
            raise ArgumentError, "object key must be a string" unless string_key.is_a?(String)
            raise ArgumentError, "duplicate object key #{string_key.inspect}" if memo.key?(string_key)

            memo[string_key] = val
          end
          ordered = string_keys.keys.sort_by { |k| utf16_code_units(k) }
          parts = ordered.map { |k| encode_string(k) + ":" + encode_value(string_keys.fetch(k)) }
          "{" + parts.join(",") + "}"
        end

        # Convert a UTF-8 string into an array of UTF-16 code units for ordering (RFC 8785 sec 3.2.3).
        def utf16_code_units(string)
          # encode! through UTF-16BE then split into 16-bit units; sort_by uses array comparison.
          utf16 = string.encode("UTF-16BE", invalid: :replace, undef: :replace).bytes
          units = []
          i = 0
          while i < utf16.length
            units << ((utf16[i] << 8) | utf16[i + 1])
            i += 2
          end
          units
        end

        # ES6 ToString (ECMA-262 7.1.12.1) number serialization for JCS (RFC 8785 sec 3.2.2.3).
        #
        # Mirrors V8/JavaScriptCore semantics: plain decimal notation when the shortest
        # round-trip representation has decimal exponent k with -6 < k <= 20, exponential
        # form ("Ne+EE") otherwise.
        def encode_number(value)
          raise ArgumentError, "cannot encode NaN" if value.nan?
          raise ArgumentError, "cannot encode Infinity" if value.infinite?
          return "0" if value.zero? # collapses -0 to "0"

          sign = value.negative? ? "-" : ""
          digits, k = shortest_digits_and_exponent(value.abs)
          format_es6_number(sign, digits, k)
        end

        # Return [digits, k] where digits is the shortest decimal mantissa and k is the
        # decimal exponent of the leading digit, so that value = 0.<digits> * 10^(k+1).
        def shortest_digits_and_exponent(abs_value)
          repr = abs_value.to_s # Ruby Float#to_s is shortest-round-trip.
          if repr.include?("e")
            mantissa, exp_str = repr.split("e")
            exp_int = exp_str.to_i
          else
            mantissa = repr
            exp_int = 0
          end
          int_part, frac_part = mantissa.split(".")
          frac_part ||= ""
          combined = int_part + frac_part
          # k_repr: the exponent of the leading digit if we treat 'combined' as 0.<combined> * 10^(int_part.length + exp_int).
          # i.e. value = combined * 10^(exp_int - frac_part.length).
          # decimal_exponent_of_leading_nonzero = (exp_int + int_part.length) - (number of leading zeros stripped) - 1.
          stripped = combined.sub(/\A0+/, "")
          leading_zeros = combined.length - stripped.length
          digits = stripped.sub(/0+\z/, "")
          digits = "0" if digits.empty?
          decimal_exponent = exp_int + int_part.length - 1 - leading_zeros
          [digits, decimal_exponent]
        end

        # Render digits + decimal exponent k as ES6 ToString.
        # Uses plain decimal when -6 < k <= 20, otherwise exponential.
        def format_es6_number(sign, digits, k)
          n = digits.length
          if k.between?(0, 20)
            if n <= k + 1
              return sign + digits + ("0" * (k + 1 - n))
            end
            return sign + digits[0, k + 1] + "." + digits[(k + 1)..]
          end
          if k < 0 && k > -7
            return sign + "0." + ("0" * (-k - 1)) + digits
          end
          mantissa = (n == 1) ? digits : (digits[0] + "." + digits[1..])
          exp_sign = (k >= 0) ? "+" : "-"
          sign + mantissa + "e" + exp_sign + k.abs.to_s
        end

        ESCAPE_TABLE = {
          "\b" => "\\b",
          "\t" => "\\t",
          "\n" => "\\n",
          "\f" => "\\f",
          "\r" => "\\r",
          "\"" => "\\\"",
          "\\" => "\\\\"
        }.freeze

        # Emit a JCS-conformant JSON string literal (RFC 8785 sec 3.2.2.2), rejecting lone surrogates.
        def encode_string(string)
          raise ArgumentError, "object key must be a string" unless string.is_a?(String)

          # Validate UTF-8 and reject any string containing a lone surrogate codepoint.
          codepoints = string.encode(Encoding::UTF_8).codepoints
          codepoints.each do |cp|
            raise ArgumentError, "lone surrogate in string" if cp.between?(0xD800, 0xDFFF)
          end

          buf = +"\""
          codepoints.each do |cp|
            buf << if (esc = ESCAPE_TABLE[[cp].pack("U")])
              esc
            elsif cp < 0x20
              format("\\u%04x", cp)
            elsif cp <= 0x7E
              cp.chr(Encoding::UTF_8)
            else
              # Non-ASCII: emit raw UTF-8 (JCS does not normalize, RFC 8785 sec 3.2.4).
              [cp].pack("U")
            end
          end
          buf << "\""
          buf
        end
      end
    end
  end
end
