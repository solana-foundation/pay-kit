# frozen_string_literal: true

require_relative "pay_core"

require_relative "mpp/version"
require_relative "mpp/error"
require_relative "mpp/expires"
require_relative "mpp/store"
require_relative "mpp/challenge"
require_relative "mpp/settlement"

require_relative "mpp/protocol/core/challenge"
require_relative "mpp/protocol/core/credential"
require_relative "mpp/protocol/core/receipt"
require_relative "mpp/protocol/core/headers"
require_relative "mpp/protocol/core/challenge_store"
require_relative "mpp/protocol/intents/charge"
require_relative "mpp/protocol/solana/verification_result"
require_relative "mpp/protocol/solana/verifier"
require_relative "mpp/protocol/solana"

require_relative "mpp/server/charge"
require_relative "mpp/server/decorator"
require_relative "mpp/server/middleware"

module Mpp
  DEFAULT_REALM = "MPP"

  # Build a server-side MPP instance. Pass it a method (e.g. one built by
  # Mpp::Protocol::Solana.charge), an HMAC secret_key for challenge signing,
  # a realm string for WWW-Authenticate, and an optional replay store.
  #
  #   server = Mpp.create(
  #     method:     Mpp::Protocol::Solana.charge(recipient: "...", currency: "USDC", rpc: "..."),
  #     secret_key: "secret",
  #     realm:      "My App",
  #   )
  def self.create(method:, secret_key:, realm: DEFAULT_REALM, replay_store: MemoryStore.new,
    settlement_header: Server::Charge::Handler::DEFAULT_SETTLEMENT_HEADER,
    expires_in: Protocol::Core::ChallengeStore::DEFAULT_EXPIRES_SECONDS)
    Server::Charge.new(
      method: method,
      secret_key: secret_key,
      realm: realm,
      replay_store: replay_store,
      settlement_header: settlement_header,
      expires_in: expires_in
    )
  end
end
