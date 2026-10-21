# frozen_string_literal: true

module PayCore
  # Protocol-independent ledger of Solana transaction signatures that already
  # authorized a protected response.
  #
  # MPP charge and x402 `exact` both claim here, so one on-chain payment
  # authorizes one request whichever protocol presents it: a transaction
  # settled through MPP cannot be presented again as an x402 payment on a
  # gate that shares the store, and vice versa. The key is the signature
  # alone; a signature commits to a message carrying a cluster-specific
  # blockhash, so scoping by network or protocol would only give each
  # protocol its own replay namespace. Mirrors the Rust
  # `core::store::ConsumedSignatures`.
  #
  # `store` is any object with an atomic `put_if_absent(key, value)` and a
  # read-only `key?(key)`.
  class ConsumedSignatures
    # Keys under which MPP charge and x402 `exact` claimed signatures before
    # they shared this ledger. Every claim also takes them, so that during a
    # rolling upgrade a replica still running the previous release (which
    # claims and checks only its own legacy key) sees a payment this release
    # accepted, and the other way round.
    LEGACY_KEY_PREFIXES = ["solana-charge:consumed:", "x402-svm-exact:consumed:"].freeze

    def self.key(signature)
      "solana:consumed-signature:#{signature}"
    end

    def initialize(store)
      raise ArgumentError, "consumed-signature store is required" if store.nil?
      # Checked here, not at the first claim, so a store that cannot honour
      # pre-ledger claims fails at boot instead of silently skipping them.
      raise ArgumentError, "consumed-signature store must respond to key?" unless store.respond_to?(:key?)

      @store = store
    end

    # Atomically claim `signature`. `false` means an earlier presentation,
    # through any protocol or release, already claimed it.
    #
    # The legacy keys come first, each taken with `put_if_absent`, so a
    # replica on the previous release, which claims its own legacy key the
    # same way, contends on the very same key: at most one of them wins, with
    # no window between a check and a write. A signature already held under
    # any of them stays consumed and is never migrated. The store cannot
    # delete, so a refused claim keeps the legacy keys it took; that only
    # fails closed, for a signature someone else already holds.
    def claim(signature)
      LEGACY_KEY_PREFIXES.each do |prefix|
        return false unless @store.put_if_absent("#{prefix}#{signature}", true)
      end
      @store.put_if_absent(self.class.key(signature), true)
    end

    # Whether `signature` is already claimed, through any protocol or under a
    # pre-ledger key. Read only.
    def claimed?(signature)
      consumed_before_ledger?(signature) || @store.key?(self.class.key(signature))
    end

    private

    # Whether `signature` was claimed under a pre-ledger MPP or x402 key, by a
    # replica running an older release or before this one upgraded. Read only
    # and fail closed: such a signature stays consumed, it is never migrated
    # or claimed again.
    def consumed_before_ledger?(signature)
      LEGACY_KEY_PREFIXES.any? { |prefix| @store.key?("#{prefix}#{signature}") }
    end
  end
end
