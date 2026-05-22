# frozen_string_literal: true

require "json"

module Mpp
  module Core
    # RFC 8785 canonical JSON encoder for MPP header payloads.
    #
    # Vendors a small JCS implementation rather than delegating to JSON.generate so the
    # ordering, number serialization, and surrogate validation rules match the Rust spine.
    # See RFC 8785 sec 3.2.2 and sec 3.2.3.
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
        def encode_number(value)
          raise ArgumentError, "cannot encode NaN" if value.nan?
          raise ArgumentError, "cannot encode Infinity" if value.infinite?
          return "0" if value.zero? # collapses -0 to "0"
          return value.to_i.to_s if value.finite? && value == value.to_i && value.abs < 1e21

          # Use Ruby's shortest-round-trip formatter (Float#to_s is shortest-round-trip since 2.0).
          # Then normalize to ES6 form: drop ".0" trailing on integers, use lowercase e, e+NN with sign.
          ruby_repr = value.to_s
          # Ruby Float#to_s emits "1.0e+21" for 1e21 and "1.0e-7" for 1e-7. ES6 ToString uses "1e+21" / "1e-7".
          if ruby_repr.include?("e")
            mantissa, exp = ruby_repr.split("e")
            mantissa = mantissa.sub(/\.0\z/, "")
            exp_int = exp.to_i
            sign = (exp_int >= 0) ? "+" : "-"
            "#{mantissa}e#{sign}#{exp_int.abs}"
          else
            ruby_repr.sub(/\.0\z/, "")
          end
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
