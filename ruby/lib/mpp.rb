# frozen_string_literal: true

require_relative "mpp/version"
require_relative "mpp/error"
require_relative "mpp/expires"
require_relative "mpp/store"
require_relative "mpp/core/base64_url"
require_relative "mpp/core/json"
require_relative "mpp/core/challenge"
require_relative "mpp/core/credential"
require_relative "mpp/core/receipt"
require_relative "mpp/core/headers"
require_relative "mpp/intent/charge_request"
require_relative "mpp/methods/solana/mints"
require_relative "mpp/methods/solana/base58"
require_relative "mpp/methods/solana/public_key"
require_relative "mpp/methods/solana/account"
require_relative "mpp/methods/solana/rpc"
require_relative "mpp/methods/solana/transaction"
require_relative "mpp/methods/solana/associated_token"
require_relative "mpp/methods/solana/verification_result"
require_relative "mpp/methods/solana/verifier"
require_relative "mpp/methods/solana"
require_relative "mpp/challenge"
require_relative "mpp/settlement"
require_relative "mpp/internal/challenge_store"
require_relative "mpp/internal/handler"
require_relative "mpp/server"
require_relative "mpp/server/decorator"
require_relative "mpp/server/middleware"

module Mpp
  DEFAULT_REALM = "MPP"

  # Build a server-side MPP instance. Pass it a method (e.g. one built by
  # Mpp::Methods::Solana.charge), an HMAC secret_key for challenge signing,
  # a realm string for WWW-Authenticate, and an optional replay store.
  #
  #   server = Mpp.create(
  #     method:     Mpp::Methods::Solana.charge(recipient: "...", currency: "USDC", rpc: "..."),
  #     secret_key: "secret",
  #     realm:      "My App",
  #   )
  def self.create(method:, secret_key:, realm: DEFAULT_REALM, replay_store: MemoryStore.new, settlement_header: Internal::Handler::DEFAULT_SETTLEMENT_HEADER)
    Server::Instance.new(
      method: method,
      secret_key: secret_key,
      realm: realm,
      replay_store: replay_store,
      settlement_header: settlement_header
    )
  end
end
