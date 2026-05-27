# frozen_string_literal: true

require "logger"

require_relative "local"

module PayKit
  module Signer
    # Hard-coded demo keypair shipped with the gem so that
    # `require "solana_pay_kit"` plus an empty `PayKit.configure {}` boots
    # against a local validator without forcing the developer to supply
    # any env var. The bytes below are PUBLIC; this keypair is NOT a
    # secret and MUST NOT be used in production. `PayKit::Config` enforces
    # this in two ways:
    #   1. A `Logger.warn` line is emitted the first time the demo signer
    #      is instantiated in a process.
    #   2. `PayKit.configure` raises `PayKit::DemoSignerOnMainnetError`
    #      at `freeze!` time when `c.network = :solana_mainnet` is combined
    #      with `operator.signer == Signer.demo`.
    #
    # Pubkey: ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq
    class Demo < Local
      SECRET_BYTES = [
        26, 61, 117, 192, 9, 232, 24, 51, 89, 135, 105, 182, 47, 9, 83, 244,
        11, 214, 85, 170, 227, 83, 170, 26, 55, 129, 58, 114, 89, 160, 195, 51,
        138, 209, 127, 35, 54, 41, 202, 166, 199, 166, 97, 238, 181, 63, 254, 185,
        45, 16, 174, 102, 250, 198, 30, 191, 232, 236, 147, 167, 41, 178, 151, 26
      ].freeze
      PUBKEY = "ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq"

      WARNING_MESSAGE =
        "PayKit::Signer.demo is in use. This keypair is published in the gem " \
        "source and MUST NOT be used in production. PayKit will refuse to " \
        "start when this signer is combined with :solana_mainnet."

      class << self
        # Cached instance: one Demo signer per process. Emits the boot
        # warning the first time it is materialised.
        def instance
          @instance ||= begin
            warn_once
            new(SECRET_BYTES.dup)
          end
        end

        private

        def warn_once
          return if @warned

          @warned = true
          (PayKit.logger || default_logger).warn(WARNING_MESSAGE)
        end

        def default_logger
          @default_logger ||= ::Logger.new($stderr).tap do |logger|
            logger.formatter = proc { |_severity, _datetime, _progname, msg| "[PayKit] WARN: #{msg}\n" }
          end
        end

        # Test hook: reset the cached instance and the warned-once flag.
        # Public only because the gem's own tests call it; do not rely on
        # it from application code.
        def reset!
          @instance = nil
          @warned = false
          @default_logger = nil
        end
      end

      def demo?
        true
      end
    end
  end
end
