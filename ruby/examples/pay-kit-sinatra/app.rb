# frozen_string_literal: true

require "json"
require "sinatra/base"

# Boot the gem and the opt-in Sinatra helpers. The second require is
# explicit; the gem does NOT auto-detect Sinatra at load time.
require_relative "../../lib/solana_pay_kit"
require_relative "../../lib/solana_pay_kit/sinatra"

# Boot-time configuration. Runs once at process startup; frozen after
# the block returns. Mirrors Clearance's configure pattern.
PayKit.configure do |c|
  c.pay_to = ENV.fetch("PAY_KIT_PAY_TO", "AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj")
  c.network = ENV.fetch("PAY_KIT_NETWORK", "solana_devnet").to_sym
  # Default to mpp-only so the demo boots without a real Solana
  # facilitator keypair. Set PAY_KIT_ACCEPT="x402,mpp" once
  # PAY_KIT_X402_FACILITATOR_KEY holds a valid 64-byte JSON array.
  c.accept = ENV.fetch("PAY_KIT_ACCEPT", "mpp").split(",").map(&:to_sym)
  c.stablecoins = ENV.fetch("PAY_KIT_STABLECOINS", "USDC").split(",").map(&:to_sym)

  c.x402.facilitator = ENV.fetch("PAY_KIT_X402_FACILITATOR", "https://402.surfnet.dev:8899")
  c.x402.facilitator_secret_key = ENV.fetch("PAY_KIT_X402_FACILITATOR_KEY", "[]")
  c.x402.scheme = :exact

  c.mpp.realm = ENV.fetch("PAY_KIT_MPP_REALM", "PayKit Demo")
  c.mpp.secret = ENV.fetch("PAY_KIT_MPP_SECRET", "demo-secret-do-not-use-in-prod")
end

require_relative "pricing"
PayKit.pricing = Pricing.new

# One gem, one surface. x402 and MPP both gate the same routes; the
# merchant doesn't care which protocol settled the request.
class PayKitSinatraExample < Sinatra::Base
  helpers PayKit::Sinatra
  use PayKit::Rack::PaymentRequired

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
