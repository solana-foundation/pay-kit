# frozen_string_literal: true

module PayKit
  class Error < StandardError; end

  # Raised when middleware needs to halt a request with 402. The
  # response builder reads `#challenge` to produce the 402 body and
  # protocol-specific headers.
  class PaymentRequired < Error
    attr_reader :challenge

    def initialize(challenge, message = nil)
      @challenge = challenge
      super(message || "payment required")
    end
  end

  # Raised when an inbound payment proof is structurally valid but
  # fails verification (wrong amount, wrong destination, expired,
  # replayed, signature mismatch, ...). Mapped to 402 by middleware
  # so the client can retry with a fresh challenge.
  class InvalidProof < Error
    attr_reader :detail, :code

    def initialize(code, detail = nil)
      @code = code
      @detail = detail
      super(detail || code.to_s)
    end
  end

  # Boot-time configuration error. Raised before any request is
  # served when the gate registry, fee math, or config is invalid.
  class ConfigurationError < Error; end

  # Lookup error from the Pricing registry.
  class UnknownGate < ConfigurationError
    def initialize(name)
      super("unknown gate: #{name.inspect}")
    end
  end

  # Raised when `payment` is accessed before middleware has set it.
  class NoRegistryConfigured < ConfigurationError
    def initialize
      super("no Pricing registry configured. Set PayKit.pricing = MyPricing.new at boot.")
    end
  end
end
