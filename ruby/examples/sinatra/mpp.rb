# frozen_string_literal: true

require_relative "config"

module SinatraExample
  # Builds the MPP charge handler and per-request charge factory.
  # The handler is a singleton (holds the in-memory replay store);
  # the charge request is rebuilt every call so it carries a fresh blockhash.
  module Charge
    def self.handler
      @handler ||= ::Mpp::Server::ChargeHandler.new(
        challenges:   challenges,
        rpc:          rpc,
        replay_store: ::Mpp::MemoryStore.new,
        fee_payer:    Config.fee_payer,
        network:      Config.network
      )
    end

    def self.charge_request
      method_details = {
        "network"         => Config.network,
        "decimals"        => Config.decimals,
        "tokenProgram"    => ::Mpp::Common::StablecoinMints.token_program_for(Config.mint, Config.network),
        "recentBlockhash" => rpc.latest_blockhash
      }
      if handler.fee_payer_pubkey
        method_details["feePayer"]    = true
        method_details["feePayerKey"] = handler.fee_payer_pubkey
      end

      ::Mpp::Intent::ChargeRequest.new(
        amount:         Config.amount,
        currency:       Config.mint,
        recipient:      Config.pay_to,
        description:    "Sinatra protected endpoint",
        external_id:    "ruby-sinatra-example",
        method_details: method_details
      )
    end

    def self.rpc
      @rpc ||= ::Mpp::Solana::RpcClient.new(Config.rpc_url)
    end

    def self.challenges
      @challenges ||= ::Mpp::Server::ChargeServer.new(
        secret_key: Config.secret_key,
        realm:      Config::REALM
      )
    end
  end
end
