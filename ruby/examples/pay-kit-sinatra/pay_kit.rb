# frozen_string_literal: true

# Central gates registry. One file declares every paid surface in the
# app, the way `Ability` does in CanCanCan.

class Pricing < PayKit::Pricing
  SELLER = ENV.fetch("PAY_KIT_SELLER", "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
  PLATFORM = ENV.fetch("PAY_KIT_PLATFORM", "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
  GATEWAY = ENV.fetch("PAY_KIT_GATEWAY", "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")

  def build_gates
    # Simple gate. Defaults to PayKit.config.accept (x402 + mpp) and
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
