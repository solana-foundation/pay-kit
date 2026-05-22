# frozen_string_literal: true

require_relative "../../lib/mpp"

module SinatraExample
  # Environment-driven defaults for the example app.
  # Override any of these via env vars (HOST, PORT, MPP_RPC_URL, ...).
  module Config
    DEFAULT_RPC_URL = "https://402.surfnet.dev:8899"
    DEFAULT_CURRENCY = "USDC"
    DEFAULT_PAY_TO = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
    REALM = "Ruby Sinatra Example"

    def self.host = ENV.fetch("HOST", "127.0.0.1")
    def self.port = Integer(ENV.fetch("PORT", "4568"))
    def self.rpc_url = ENV.fetch("MPP_RPC_URL", DEFAULT_RPC_URL)
    def self.network = ENV.fetch("MPP_NETWORK", "localnet")
    def self.currency = ENV.fetch("MPP_CURRENCY", DEFAULT_CURRENCY)
    def self.pay_to = ENV.fetch("MPP_PAY_TO", DEFAULT_PAY_TO)
    def self.secret_key = ENV.fetch("MPP_SECRET_KEY", "ruby-mpp-dev-secret")
    def self.amount = ENV.fetch("MPP_AMOUNT", "1000")

    # Optional server-side fee payer; returns nil when the env var is unset.
    def self.fee_payer
      secret = ENV["MPP_FEE_PAYER_SECRET_KEY"]
      return nil if secret.nil? || secret.empty?

      Mpp::Methods::Solana::Account.from_json_array(secret)
    end
  end
end
