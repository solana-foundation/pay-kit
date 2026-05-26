# frozen_string_literal: true

require_relative "../test_helper"
require "solana_pay_kit"

module PayKitTestHelpers
  # Boot a minimal PayKit config + pricing for a single test, then
  # restore the previous one. Use inside individual tests:
  #
  #   PayKitTestHelpers.with_config(accept: %i[mpp]) do
  #     # ... config-dependent code ...
  #   end
  def self.with_config(overrides = {})
    prior_config = PayKit.instance_variable_get(:@config)
    prior_pricing = PayKit.instance_variable_get(:@pricing)

    PayKit.reset!
    PayKit.configure do |c|
      c.pay_to = overrides[:pay_to] || "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"
      c.network = overrides[:network] || :solana_devnet
      c.accept = overrides[:accept] || %i[x402 mpp]
      c.stablecoins = overrides[:stablecoins] || %i[USDC]
      c.x402.facilitator = overrides[:x402_facilitator] || "https://example.test"
      c.x402.facilitator_secret_key = overrides[:x402_secret] if overrides[:x402_secret]
      c.mpp.realm = overrides[:realm] || "Test"
      c.mpp.secret = overrides[:mpp_secret] || "test-secret"
    end

    yield
  ensure
    PayKit.instance_variable_set(:@config, prior_config)
    PayKit.instance_variable_set(:@pricing, prior_pricing)
  end
end
