# frozen_string_literal: true

require "json"
require "sinatra/base"
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

# Minimal Sinatra application with one MPP-protected charge endpoint.
class RubyMppSinatraExample < Sinatra::Base
  set :bind, ENV.fetch("HOST", "127.0.0.1")
  set :port, Integer(ENV.fetch("PORT", "4568"))
  set :show_exceptions, false

  configure do
    rpc = SolanaMpp::Solana::RpcClient.new(ENV.fetch("MPP_RPC_URL", DEFAULT_RPC_URL))
    network = ENV.fetch("MPP_NETWORK", "localnet")
    mint = ENV.fetch("MPP_MINT", DEFAULT_MINT)
    challenges = SolanaMpp::Server::ChargeServer.new(
      secret_key: ENV.fetch("MPP_SECRET_KEY", "ruby-mpp-dev-secret"),
      realm: "Ruby Sinatra Example"
    )
    handler = SolanaMpp::Server::ChargeHandler.new(
      challenges: challenges,
      rpc: rpc,
      replay_store: SolanaMpp::MemoryStore.new,
      fee_payer: fee_payer_from_env,
      network: network
    )

    set :mpp_rpc, rpc
    set :mpp_network, network
    set :mpp_mint, mint
    set :mpp_handler, handler
  end

  helpers do
    # Build a fresh charge request for each protected request.
    def mpp_charge_request
      method_details = {
        "network" => settings.mpp_network,
        "decimals" => Integer(ENV.fetch("MPP_DECIMALS", "6")),
        "tokenProgram" => SolanaMpp::Common::StablecoinMints.token_program_for(settings.mpp_mint, settings.mpp_network),
        "recentBlockhash" => settings.mpp_rpc.latest_blockhash
      }
      if settings.mpp_handler.fee_payer_pubkey
        method_details["feePayer"] = true
        method_details["feePayerKey"] = settings.mpp_handler.fee_payer_pubkey
      end

      SolanaMpp::Intent::ChargeRequest.new(
        amount: ENV.fetch("MPP_AMOUNT", "1000"),
        currency: settings.mpp_mint,
        recipient: ENV.fetch("MPP_PAY_TO", DEFAULT_PAY_TO),
        description: "Sinatra protected endpoint",
        external_id: "ruby-sinatra-example",
        method_details: method_details
      )
    end
  end

  get "/health" do
    content_type :json
    JSON.generate({"ok" => true})
  end

  get "/paid" do
    payment = settings.mpp_handler.handle(request.env["HTTP_AUTHORIZATION"], mpp_charge_request)
    status payment.status
    payment.headers.each { |name, value| headers[name] = value }
    content_type :json
    JSON.generate(payment.body)
  end

  run! if app_file == $PROGRAM_NAME
end
