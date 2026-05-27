# frozen_string_literal: true

require_relative "../test_helper"
require "solana_pay_kit"

module PayKitTestHelpers
  # Boot a minimal PayKit config + pricing for a single test, then
  # restore the previous one. Uses the post-DESIGN.md surface
  # (operator block + rpc_url + challenge_binding_secret) rather than
  # the deprecated knobs, so the test suite stays free of warning
  # noise except in the few tests that explicitly exercise the shims.
  #
  # Recognised overrides:
  #   :network, :accept, :stablecoins, :rpc_url
  #   :pay_to              shorthand for operator.recipient (string)
  #   :signer              PayKit::Signer (anything responding to
  #                        #pubkey/#sign/#fee_payer?)
  #   :fee_payer           explicit true/false override
  #   :realm, :mpp_secret  MPP knobs (challenge_binding_secret)
  #   :x402_signer         advanced c.x402.signer override
  #   :x402_facilitator_url  delegated facilitator URL (left nil = self-hosted)
  def self.with_config(overrides = {})
    prior_config = PayKit.instance_variable_get(:@config)
    prior_pricing = PayKit.instance_variable_get(:@pricing)

    PayKit.reset!
    PayKit.configure do |c|
      c.network = overrides[:network] || :solana_devnet
      c.accept = overrides[:accept] || %i[x402 mpp]
      c.stablecoins = overrides[:stablecoins] || %i[USDC]
      c.rpc_url = overrides[:rpc_url] || "https://example.test"

      c.operator do |op|
        op.recipient = overrides[:pay_to] || "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj"
        op.signer = overrides[:signer]
        op.fee_payer = overrides[:fee_payer]
      end

      c.x402.facilitator_url = overrides[:x402_facilitator_url]
      c.x402.signer = overrides[:x402_signer]
      c.mpp.realm = overrides[:realm] || "Test"
      c.mpp.challenge_binding_secret = overrides[:mpp_secret] || "test-secret"
      c.mpp.expires_in = overrides[:mpp_expires_in] if overrides.key?(:mpp_expires_in)
    end

    yield
  ensure
    PayKit.instance_variable_set(:@config, prior_config)
    PayKit.instance_variable_set(:@pricing, prior_pricing)
  end
end
