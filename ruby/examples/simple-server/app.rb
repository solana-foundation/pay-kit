# frozen_string_literal: true

require "json"
require "webrick"
require_relative "../../lib/mpp"

DEFAULT_RPC_URL = "https://402.surfnet.dev:8899"
DEFAULT_CURRENCY = "USDC"
DEFAULT_PAY_TO = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

# Optional server-side fee payer, loaded from a JSON-array secret key.
def fee_payer_from_env
  secret = ENV["MPP_FEE_PAYER_SECRET_KEY"]
  return nil if secret.nil? || secret.empty?

  Mpp::Methods::Solana::Account.from_json_array(secret)
end

# Configure the Solana charge method (recipient, currency, network, RPC, fee payer)
# and build the MPP server. The method bundles every static knob; per-request
# only amount + description are passed to server.charge.
method = Mpp::Methods::Solana.charge(
  recipient: ENV.fetch("MPP_PAY_TO", DEFAULT_PAY_TO),
  currency: ENV.fetch("MPP_CURRENCY", DEFAULT_CURRENCY),
  network: ENV.fetch("MPP_NETWORK", "localnet"),
  rpc: ENV.fetch("MPP_RPC_URL", DEFAULT_RPC_URL),
  fee_payer: fee_payer_from_env
)
server = Mpp.create(method: method, secret_key: ENV.fetch("MPP_SECRET_KEY", "ruby-mpp-dev-secret"), realm: "Ruby MPP Example")

http = WEBrick::HTTPServer.new(
  BindAddress: "127.0.0.1",
  Port: Integer(ENV.fetch("PORT", "4567")),
  AccessLog: [],
  Logger: WEBrick::Log.new($stderr, WEBrick::Log::INFO)
)

http.mount_proc "/health" do |_req, res|
  res.status = 200
  res["content-type"] = "application/json"
  res.body = JSON.generate(ok: true)
end

http.mount_proc "/paid" do |req, res|
  result = server.charge(req["authorization"], amount: "1000", description: "Ruby protected endpoint")

  case result
  when Mpp::Challenge
    res.status = result.status
    result.headers.each { |name, value| res[name] = value }
    res["content-type"] = "application/json"
    res.body = JSON.generate(result.body)
  when Mpp::Settlement
    res.status = result.status
    result.headers.each { |name, value| res[name] = value }
    res["content-type"] = "application/json"
    res.body = JSON.generate(ok: true, paid: true)
  end
end

trap("INT") { http.shutdown }
trap("TERM") { http.shutdown }
http.start
