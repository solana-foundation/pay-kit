# frozen_string_literal: true

# Canonical entry point for the `solana-pay-kit` gem. Matches the gem
# name (`gem install solana-pay-kit`, `require "solana_pay_kit"`).
#
# Loads the protocol layers and the high-level `PayKit` umbrella, then
# auto-detects Sinatra. The Sinatra hook fires in both load orders:
#
#   require "sinatra/base"; require "solana_pay_kit"   -> registers immediately
#   require "solana_pay_kit"; require "sinatra/base"   -> registers via TracePoint
#
# Apps that don't use Sinatra never trip the autoload. Apps that prefer
# explicit wiring can still write `helpers PayKit::Sinatra` /
# `use PayKit::Rack::PaymentRequired` themselves; the auto-registration
# is idempotent.
require_relative "pay_kit"

module PayKit
  # Internal: idempotent Sinatra-registration helper. Public surface
  # stays through the regular PayKit::Sinatra + PayKit::Rack constants;
  # this module just decides when to call `helpers` + `use`.
  module SinatraAutoRegister
    @registered = false

    def self.try_register!
      return unless defined?(::Sinatra::Base)
      return if @registered

      require_relative "pay_kit/sinatra"
      ::Sinatra::Base.helpers(::PayKit::Sinatra)
      ::Sinatra::Base.use(::PayKit::Rack::PaymentRequired)
      @registered = true
    end

    def self.registered?
      @registered
    end

    # Test-only: forget the registration so a follow-up `try_register!`
    # repeats the work. Production callers never touch this.
    def self.reset!
      @registered = false
    end
  end
end

PayKit::SinatraAutoRegister.try_register!

unless PayKit::SinatraAutoRegister.registered?
  # Sinatra wasn't loaded yet. Watch for the END of the Sinatra::Base
  # class body (`:end` event, not `:class` - the latter fires before
  # the body runs, when `helpers` is still undefined). TracePoint
  # disables itself after firing so there is no ongoing tracing
  # overhead for the rest of the process.
  paykit_sinatra_trace = TracePoint.new(:end) do |tp|
    if tp.self.name == "Sinatra::Base"
      PayKit::SinatraAutoRegister.try_register!
      paykit_sinatra_trace.disable
    end
  end
  paykit_sinatra_trace.enable
end
