# frozen_string_literal: true

# Smallest possible pay-kit server: one gated endpoint, plain Rack, no
# framework. Run it with `rackup` from this directory and drive it with
# `curl` (402) then `pay curl` (200).
#
# Sensible defaults: the demo keypair is the recipient and the hosted
# Surfpool RPC settles the charge, so this boots with zero configuration.

require "json"
require "rack"

# In a real app this is just `require "solana_pay_kit"` after
# `gem install solana-pay-kit`. Running from the repo, point Ruby at the
# in-tree library.
$LOAD_PATH.unshift(File.expand_path("../../lib", __dir__))
require "pay_kit"

PayKit.configure do |c|
  c.network = :solana_localnet
  c.accept = %i[x402 mpp]
  # MPP signs its 402 challenges with this HMAC secret. A real
  # deployment loads it from a secret store; the demo uses a fixed
  # value so the server boots with no setup.
  c.mpp.challenge_binding_secret = "simple-server-demo-secret"
end

# One gate: $0.10, settled in any configured stablecoin.
class Pricing < PayKit::Pricing
  def build_gates
    gate :report, amount: usd("0.10"), description: "Premium report"
  end
end

PayKit.pricing = Pricing.new

# Plain Rack endpoint. It asks the dispatcher (installed on the env by
# PayKit::Rack::PaymentRequired) whether the request carries a valid
# proof for the `:report` gate. No proof: reply 402 with the challenge.
# Valid proof: serve the body and let the middleware attach the receipt.
class SimpleServer
  GATE = :report

  def call(env)
    request = Rack::Request.new(env)
    return json(200, ok: true) if request.path == "/health"

    dispatcher = env.fetch(PayKit::Rack::PaymentRequired::ENV_DISPATCHER_KEY)
    gate = PayKit.pricing[GATE]

    begin
      proof = dispatcher.verify(gate, request)
    rescue PayKit::InvalidProof => e
      return PayKit::Rack::PaymentRequired.render_invalid(e)
    end

    unless proof
      return PayKit::Rack::PaymentRequired.render_402(dispatcher.challenge_for(gate, request))
    end

    env[PayKit::Rack::PaymentRequired::ENV_PAYMENT_KEY] = proof
    json(200, ok: true, paid_by: proof.protocol)
  end

  private

  def json(status, payload)
    [status, {"content-type" => "application/json"}, [JSON.generate(payload)]]
  end
end

# The runnable Rack app. `config.ru` mounts this under `rackup`.
SIMPLE_SERVER_APP = Rack::Builder.new do
  use PayKit::Rack::PaymentRequired
  run SimpleServer.new
end.to_app
