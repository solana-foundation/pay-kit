# frozen_string_literal: true

# Boot file for the pay-kit demo. One file holds both the gem
# configuration block and the gates registry, mirroring how a Rails
# app would scaffold `config/initializers/solana_pay_kit.rb`.
#
# Loaded by app.rb via `require_relative "pay_kit"`.

PayKit.configure do |c|
  c.pay_to = ENV.fetch("PAY_KIT_PAY_TO", "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
  c.network = :solana_localnet
  # Default to mpp-only so the demo boots without a real Solana
  # facilitator keypair. Set PAY_KIT_ACCEPT="x402,mpp" once
  # PAY_KIT_X402_FACILITATOR_KEY holds a valid 64-byte JSON array.
  c.accept = ENV.fetch("PAY_KIT_ACCEPT", "mpp").split(",").map(&:to_sym)
  c.x402.facilitator = ENV.fetch("PAY_KIT_X402_FACILITATOR", "https://402.surfnet.dev:8899")
  c.x402.facilitator_secret_key = ENV.fetch("PAY_KIT_X402_FACILITATOR_KEY", "[]")
  c.mpp.secret = ENV.fetch("PAY_KIT_MPP_SECRET", "demo-secret-do-not-use-in-prod")
end

# Central gates registry. One class declares every paid surface in
# the app, the way `Ability` does in CanCanCan.
class Pricing < PayKit::Pricing
  SELLER = ENV.fetch("PAY_KIT_SELLER", "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
  PLATFORM = ENV.fetch("PAY_KIT_PLATFORM", "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
  GATEWAY = ENV.fetch("PAY_KIT_GATEWAY", "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")

  def build_gates
    # Simple gate. Defaults to PayKit.config.accept and
    # PayKit.config.pay_to. Customer pays $0.10, pay_to nets $0.10.
    gate :report,
      amount: usd("0.10"),
      description: "Premium report"

    # x402-only gate.
    gate :api_call,
      amount: usd("0.001"),
      accept: :x402,
      description: "API call"

    # Stripe Connect "application fee" pattern. Customer pays $10.00,
    # SELLER nets $9.70, PLATFORM nets $0.30. x402 auto-disabled
    # because stock x402 facilitators settle to one address.
    gate :marketplace_sale,
      amount: usd("10.00"),
      pay_to: SELLER,
      fee_within: {PLATFORM => usd("0.30")},
      description: "Marketplace sale"

    # Surcharge pattern. Customer pays $10.50, SELLER nets $10.00,
    # PLATFORM nets $0.50.
    gate :ticket,
      amount: usd("10.00"),
      pay_to: SELLER,
      fee_on_top: {PLATFORM => usd("0.50")},
      description: "Ticket"

    # Dynamic pricing. The block runs per-request against the
    # incoming Rack request and uses the same setter DSL as the
    # static form.
    gate :tiered do |request|
      amount usd((request.params["tier"] == "premium") ? "5.00" : "0.10")
    end
  end
end

PayKit.pricing = Pricing.new
