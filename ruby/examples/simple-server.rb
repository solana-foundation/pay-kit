# frozen_string_literal: true

require "json"
require "webrick"
require_relative "../lib/solana_mpp"

DEFAULT_RPC_URL = "https://402.surfnet.dev:8899"
DEFAULT_MINT = "USDC"
DEFAULT_PAY_TO = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

# Build the optional fee payer from environment variables.
def fee_payer_from_env
  secret = ENV["MPP_FEE_PAYER_SECRET_KEY"]
  return nil if secret.nil? || secret.empty?

  SolanaMpp::Solana::Keypair.from_json_array(secret)
end

# Build a charge handler from environment variables for local manual testing.
def build_handler
  rpc = SolanaMpp::Solana::RpcClient.new(ENV.fetch("MPP_RPC_URL", DEFAULT_RPC_URL))
  challenges = SolanaMpp::Server::ChargeServer.new(
    secret_key: ENV.fetch("MPP_SECRET_KEY", "ruby-mpp-dev-secret"),
    realm: "Ruby MPP Example"
  )
  SolanaMpp::Server::ChargeHandler.new(
    challenges: challenges,
    rpc: rpc,
    replay_store: SolanaMpp::MemoryStore.new,
    fee_payer: fee_payer_from_env,
    network: ENV.fetch("MPP_NETWORK", "localnet")
  )
end

# Build the protected charge request with a fresh blockhash.
def build_request(handler)
  rpc = SolanaMpp::Solana::RpcClient.new(ENV.fetch("MPP_RPC_URL", DEFAULT_RPC_URL))
  network = ENV.fetch("MPP_NETWORK", "localnet")
  mint = ENV.fetch("MPP_MINT", DEFAULT_MINT)
  method_details = {
    "network" => network,
    "decimals" => Integer(ENV.fetch("MPP_DECIMALS", "6")),
    "tokenProgram" => SolanaMpp::Common::StablecoinMints.token_program_for(mint, network),
    "recentBlockhash" => rpc.latest_blockhash
  }
  if handler.fee_payer_pubkey
    method_details["feePayer"] = true
    method_details["feePayerKey"] = handler.fee_payer_pubkey
  end

  SolanaMpp::Intent::ChargeRequest.new(
    amount: ENV.fetch("MPP_AMOUNT", "1000"),
    currency: mint,
    recipient: ENV.fetch("MPP_PAY_TO", DEFAULT_PAY_TO),
    description: "Ruby protected endpoint",
    external_id: "ruby-simple-server",
    method_details: method_details
  )
end

handler = build_handler
server = WEBrick::HTTPServer.new(
  BindAddress: "127.0.0.1",
  Port: Integer(ENV.fetch("PORT", "4567")),
  AccessLog: [],
  Logger: WEBrick::Log.new($stderr, WEBrick::Log::INFO)
)

server.mount_proc "/health" do |_req, res|
  res.status = 200
  res["content-type"] = "application/json"
  res.body = JSON.generate({"ok" => true})
end

server.mount_proc "/paid" do |req, res|
  payment = handler.handle(req["authorization"], build_request(handler))
  res.status = payment.status
  payment.headers.each { |name, value| res[name] = value }
  res.body = JSON.generate(payment.body)
end

trap("INT") { server.shutdown }
trap("TERM") { server.shutdown }
server.start
