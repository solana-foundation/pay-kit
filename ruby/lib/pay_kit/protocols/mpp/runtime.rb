# frozen_string_literal: true

require_relative "../../../pay_core"

require_relative "version"
require_relative "error"
require_relative "expires"
require_relative "store"
require_relative "challenge"
require_relative "settlement"

require_relative "protocol/core/challenge"
require_relative "protocol/core/credential"
require_relative "protocol/core/receipt"
require_relative "protocol/core/headers"
require_relative "protocol/core/challenge_store"
require_relative "protocol/intents/charge"
require_relative "protocol/solana/verification_result"
require_relative "protocol/solana/verifier"
require_relative "protocol/solana"

require_relative "server/charge"
require_relative "server/decorator"
require_relative "server/middleware"

module PayKit::Protocols::Mpp
  # Sentinel meaning "caller did not pass an explicit realm" so we can derive
  # a per-recipient default (audit #15) instead of sharing one hardcoded
  # namespace across every server. An explicit realm (including an explicit
  # empty string, which is rejected) is honoured as-is.
  DEFAULT_REALM = :__mpp_default_realm__

  # Sentinel used to detect when the caller did not pass an explicit
  # replay store. The sentinel allows us to distinguish "caller passed
  # nil" (an error) from "caller never passed replay_store at all"
  # (where we emit a dev-only warning and fall back to MemoryStore).
  DEV_ONLY_MEMORY_STORE = :__mpp_dev_only_memory_store__
  private_constant :DEV_ONLY_MEMORY_STORE

  # Build a server-side MPP instance. Pass it a method (e.g. one built by
  # PayKit::Protocols::Mpp::Protocol::Solana.charge), an HMAC secret_key for challenge signing,
  # a realm string for WWW-Authenticate, and an optional replay store.
  #
  #   server = PayKit::Protocols::Mpp.create(
  #     method:     PayKit::Protocols::Mpp::Protocol::Solana.charge(recipient: "...", currency: "USDC", rpc: "..."),
  #     secret_key: "secret",
  #     realm:      "My App",
  #   )
  #
  # PRODUCTION NOTE: `replay_store` defaults to a volatile in-memory store on
  # localnet only. Non-localnet servers must supply a durable, process-shared
  # store to retain replay markers across restarts and workers.
  def self.create(method:, secret_key:, realm: DEFAULT_REALM, replay_store: DEV_ONLY_MEMORY_STORE,
    settlement_header: Server::Charge::Handler::DEFAULT_SETTLEMENT_HEADER,
    expires_in: Protocol::Core::ChallengeStore::DEFAULT_EXPIRES_SECONDS)
    if replay_store == DEV_ONLY_MEMORY_STORE
      unless localnet?(method)
        raise ::PayKit::ConfigurationError,
          "PayKit::Protocols::Mpp.create requires a durable replay_store for #{network_name(method)}"
      end

      warn "[Mpp] WARNING: no replay_store supplied to PayKit::Protocols::Mpp.create — " \
           "defaulting to volatile MemoryStore. Replay markers are lost on " \
           "process restart and are NOT shared across workers or hosts. " \
           "Supply a durable shared store outside localnet."
      replay_store = MemoryStore.new
    end

    if replay_store.nil?
      raise ::PayKit::ConfigurationError,
        "PayKit::Protocols::Mpp.create requires a replay_store; nil is not a valid store"
    end

    unless localnet?(method) || durable_shared_replay_store?(replay_store)
      raise ::PayKit::ConfigurationError,
        "PayKit::Protocols::Mpp.create requires a durable replay_store shared across workers for #{network_name(method)}"
    end
    Server::Charge.new(
      method: method,
      secret_key: secret_key,
      realm: realm,
      replay_store: replay_store,
      settlement_header: settlement_header,
      expires_in: expires_in
    )
  end

  def self.localnet?(method)
    method.respond_to?(:network) && method.network.to_s == Protocol::Solana::NETWORK_LOCALNET
  end
  private_class_method :localnet?

  def self.network_name(method)
    method.respond_to?(:network) ? method.network : "non-localnet"
  end
  private_class_method :network_name

  def self.durable_shared_replay_store?(store)
    store.respond_to?(:durable?) && store.durable? &&
      store.respond_to?(:shared?) && store.shared?
  end
  private_class_method :durable_shared_replay_store?
end
