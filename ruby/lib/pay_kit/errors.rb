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
    attr_reader :detail, :code, :spec_code

    # `code` is the PayKit-level error symbol (e.g. :payment_required,
    # :payment_invalid). `spec_code` is the canonical L6 wire code from
    # the underlying protocol (e.g. "challenge_expired", "replay",
    # "amount_mismatch"). Both are surfaced on the 402 body so clients
    # can branch on either layer.
    def initialize(code, detail = nil, spec_code: nil)
      @code = code
      @detail = detail
      @spec_code = spec_code
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

  # Raised by `PayKit.configure` when `c.network = :solana_mainnet` is
  # combined with the demo signer (`PayKit::Signer.demo`). The demo
  # keypair is published in the gem source and would otherwise let a
  # misconfigured production app receive real funds to a publicly known
  # address. Switch to a real keypair (`PayKit::Signer.env`,
  # `Signer.file`, etc.) or change the network.
  class DemoSignerOnMainnetError < ConfigurationError
    def initialize(pubkey)
      super(
        "PayKit::Signer.demo (#{pubkey}) cannot be used on :solana_mainnet. " \
        "Configure a real signer via PayKit::Signer.env / .file / .json / .base58 / .hex, " \
        "or switch c.network to :solana_devnet or :solana_localnet."
      )
    end
  end

  # Raised when an API surface is reserved but not yet implemented. Used
  # for `PayKit::Kms.*` factories and (currently) the x402 delegated
  # facilitator client until the HTTP /verify + /settle path lands in a
  # follow-up release. Loud failure on purpose: silent fallback would
  # mask production misconfiguration.
  class NotImplementedError < Error; end
end
