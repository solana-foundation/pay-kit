# frozen_string_literal: true

require_relative "config"

module SinatraExample
  # Builds the Mpp::Server::Instance for this example. Memoized so the
  # in-memory replay store and the cached blockhash are shared across requests.
  def self.server
    @server ||= ::Mpp.create(
      method: ::Mpp::Methods::Solana.charge(
        recipient: Config.pay_to,
        currency: Config.currency,
        network: Config.network,
        rpc: Config.rpc_url,
        fee_payer: Config.fee_payer
      ),
      secret_key: Config.secret_key,
      realm: Config::REALM
    )
  end
end
