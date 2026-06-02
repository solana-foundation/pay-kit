# frozen_string_literal: true

# `solana-pay-kit` umbrella. Loads the shared `PayCore` primitives, the
# protocol layers (`Mpp`, `X402`), and the high-level `PayKit` surface
# that unifies them.
#
# Layout:
#
#  -----------------------------------------------------------
# |                  solana-pay-kit (PayKit)                  |
#  -----------------------------------------------------------
# |   solana-mpp        |     solana-x402                     |
#  -----------------------------------------------------------
# |                  solana-pay-core                          |
#  -----------------------------------------------------------
#
# Surface:
#
#   PayKit::Config              boot-time configuration (PayKit.configure)
#   PayKit::Pricing             registry base class + gate DSL
#   PayKit::Gate, ::Price, ...  frozen value objects (Data.define)
#   PayKit::Protocols::{X402,MPP} protocol adapters
#   PayKit::Rack::PaymentRequired   Rack middleware
#   PayKit::Sinatra             opt-in via "solana_pay_kit/sinatra"
#   PayKit::Controller          opt-in via "solana_pay_kit/rails"
#
# Framework shims are opt-in to keep require-time side effects to
# zero (no auto-detect, no spooky load-order failures).

require_relative "pay_core"

require_relative "pay_kit/errors"
require_relative "pay_kit/signer"
require_relative "pay_kit/kms"
require_relative "pay_kit/operator"
require_relative "pay_kit/price"
require_relative "pay_kit/fee"
require_relative "pay_kit/gate"
require_relative "pay_kit/dynamic_gate"
require_relative "pay_kit/config"
require_relative "pay_kit/pricing"
require_relative "pay_kit/challenge"
require_relative "pay_kit/protocols"
require_relative "pay_kit/rack/payment_required"

module PayKit
  Core = ::PayCore

  # Logger used by demo-signer warnings and any other library-level
  # diagnostic output. Defaults to a `$stderr`-backed `::Logger` the
  # first time it is referenced. Apps that integrate Rails/Sinatra can
  # assign their own logger to keep PayKit messages alongside the rest
  # of the application log.
  class << self
    attr_writer :logger

    def logger
      @logger ||= nil
    end
  end
end
