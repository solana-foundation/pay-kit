# frozen_string_literal: true

module PayCore
  # Generic HTTP auth-scheme + auth-param parser per RFC 7235 sec 2.1
  # and 4.1, shared by the MPP and x402 protocol layers. Protocol-specific
  # bindings (e.g. constructing a protocol challenge from a parsed
  # `Payment` challenge) live in their respective layers; this module
  # only owns the tokenisation, quote-aware splitting, escaping, and
  # auth-param key/value parsing.
  module Headers
    PAYMENT_SCHEME = "Payment"

    # RFC 7230 sec 3.2.6 tchar.
    TCHAR_EXTRA = "!#$%&'*+-.^_`|~"

    module_function

    # Split a WWW-Authenticate header value into individual Payment
    # challenge chunks (quote-aware). Detects RFC 7235 sec 2.1
    # auth-scheme boundaries so a Payment challenge is terminated
    # correctly when followed by another scheme on the same header line.
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

    def token_char?(ch)
      return false unless ch

      ch.match?(/[A-Za-z0-9]/) || TCHAR_EXTRA.include?(ch)
    end

    # If `bytes[index]` starts an auth-scheme (RFC 7235 sec 2.1), return
    # [offset_after_scheme, is_payment_scheme]. Otherwise return nil.
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

    # Strip the leading "Payment " scheme tag from a challenge value.
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

    # Escape an auth-param value for embedding in a quoted-string. RFC
    # 9110 sec 5.5 forbids CR and LF in header field values; raise rather
    # than silently strip so the problem surfaces at emission time.
    def escape(value)
      string = value.to_s
      raise ArgumentError, "control character in header parameter value" if string.match?(/[\r\n]/)

      string.gsub("\\", "\\\\\\").gsub("\"", "\\\"")
    end
  end
end
