# frozen_string_literal: true

require "json"
require "sinatra/base"

# A single require is enough: `solana_pay_kit` auto-detects Sinatra
# and registers `PayKit::Sinatra` helpers + `PayKit::Rack::PaymentRequired`
# middleware on Sinatra::Base in both load orders.
require_relative "../../lib/solana_pay_kit"

# Single setup file: PayKit.configure block + Pricing class +
# PayKit.pricing= assignment. Mirrors a Rails initializer.
require_relative "pay_kit"

# One gem, one surface. x402 and MPP both gate the same routes; the
# merchant doesn't care which protocol settled the request.
class SinatraExample < Sinatra::Base
  # Let PayKit's PaymentRequired/InvalidProof bubble up to the Rack
  # middleware so it can serialize the 402.
  set :show_exceptions, false
  set :raise_errors, true

  before "/admin/*" do
    require_payment! :report # any registered gate works here
  end

  get "/health" do
    content_type :json
    JSON.generate(ok: true)
  end

  # Registry lookup. Halts with 402 if unpaid; on success `payment`
  # is the verified proof.
  get "/report" do
    require_payment! :report
    content_type :json
    JSON.generate(ok: true, paid_by: payment.protocol, scheme: payment.scheme)
  end

  # Opportunistic gating. `paid?` never halts; returns true if the
  # client volunteered a valid proof for this gate.
  get "/stats" do
    content_type :json
    JSON.generate(ok: true, premium: paid?(:report))
  end

  # Inline form. No registry entry, just an amount and a description.
  get "/oneoff" do
    require_payment! usd("0.25"), description: "One-off"
    content_type :json
    JSON.generate(ok: true)
  end

  # Dynamic pricing. The registry resolves the gate fresh per request.
  get "/tiered" do
    require_payment! :tiered
    content_type :json
    JSON.generate(ok: true, tier: params["tier"] || "basic")
  end

  # Multi-recipient via fee_within. MPP-only at the protocol level.
  get "/marketplace/sale" do
    require_payment! :marketplace_sale
    content_type :json
    JSON.generate(ok: true, paid_by: payment.protocol)
  end
end
