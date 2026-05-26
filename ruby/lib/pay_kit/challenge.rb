# frozen_string_literal: true

require_relative "errors"

module PayKit
  # Per-request payment challenge. Built fresh by the middleware
  # from `Gate + Request`; never cached. Carries the ordered list
  # of `accepts` entries plus protocol-specific headers (e.g.
  # MPP's `WWW-Authenticate: Payment` realm/nonce).
  #
  # The middleware serializes this into a 402 response. Apps that
  # rescue `PaymentRequired` can read `error.challenge` to inspect
  # the same data.
  Challenge = Data.define(:resource, :accepts, :headers) do
    # Default JSON body shape for 402 responses. Apps can override
    # by reading `accepts` and serializing themselves.
    def to_h
      {
        error: "payment_required",
        resource: resource,
        accepts: accepts
      }
    end
  end

  # Payment proof received from the client and verified. Stored
  # on `request.env["pay_kit.payment"]` after middleware succeeds.
  #
  # `protocol` is the outer dispatcher (`:x402` | `:mpp`).
  # `scheme` is the sub-form (x402: `:exact`; MPP: `:charge`).
  # `transaction` is the on-chain signature (base58 string).
  # `settlement_headers` are protocol-specific response headers
  # the middleware appends to the eventual 2xx (e.g. x402's
  # `X-PAYMENT-RESPONSE`).
  Payment = Data.define(:protocol, :scheme, :transaction, :settlement_headers, :raw) do
    def x402?
      protocol == :x402
    end

    def mpp?
      protocol == :mpp
    end
  end
end
