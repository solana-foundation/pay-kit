# frozen_string_literal: true

require "json"

module Mpp
  module Core
    # RFC8785-style canonical JSON encoder for MPP header payloads.
    module Json
      module_function

      # Encode a Ruby object with stable object key ordering.
      def canonical_generate(value)
        case value
        when Hash
          "{" + value.keys.map(&:to_s).sort.map { |key|
            JSON.generate(key) + ":" + canonical_generate(value.fetch(key) { value.fetch(key.to_sym) })
          }.join(",") + "}"
        when Array
          "[" + value.map { |item| canonical_generate(item) }.join(",") + "]"
        when String, Integer, Float, TrueClass, FalseClass, NilClass
          JSON.generate(value)
        else
          raise ArgumentError, "unsupported JSON value #{value.class}"
        end
      end

      # Decode JSON and preserve object keys as strings.
      def parse(value)
        JSON.parse(value)
      rescue JSON::ParserError => error
        raise ArgumentError, "invalid JSON: #{error.message}"
      end
    end
  end
end
