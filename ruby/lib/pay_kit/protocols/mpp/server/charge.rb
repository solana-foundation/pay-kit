# frozen_string_literal: true

require "base64"
require "digest"

require "pay_core/consumed_signatures"
require "pay_core/error_codes"
require "pay_core/solana/base58"
require "pay_core/solana/transaction"
require "pay_core/solana/rpc"

module PayKit::Protocols::Mpp
  module Server
    # User-facing MPP charge server. Build one with `PayKit::Protocols::Mpp.create(method:, ...)`.
    #
    #   server = PayKit::Protocols::Mpp.create(method: ...)
    #   result = server.charge(authorization_header, amount: "1000", description: "Paid")
    #   case result
    #   when PayKit::Protocols::Mpp::Challenge  then # render 402
    #   when PayKit::Protocols::Mpp::Settlement then # render 200, include result.receipt_header
    #   end
    #
    # Mirrors `rust/crates/mpp/src/server/charge.rs`. The underlying
    # orchestrator (verify, settle, consume, receipt) lives in the nested
    # `Handler` class.
    class Charge
      # NIST SP 800-107 guidance for HMAC-SHA256: the key should be at least
      # the hash output length (32 bytes). The challenge HMAC secret binds
      # challenge IDs, so a weak key lets an attacker forge challenges
      # (audit #24). Mirrors the Rust spine MIN_SECRET_KEY_BYTES.
      MIN_SECRET_KEY_BYTES = 32

      attr_reader :method, :realm

      def initialize(method:, secret_key:, realm:, replay_store:,
        settlement_header: Handler::DEFAULT_SETTLEMENT_HEADER,
        expires_in: ::PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore::DEFAULT_EXPIRES_SECONDS)
        @method = method
        validate_secret_key!(secret_key)
        @realm = resolve_realm(realm, method.recipient)
        @challenge_store = ::PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(
          secret_key: secret_key,
          realm: @realm,
          default_expires_seconds: expires_in
        )
        @handler = Handler.new(
          challenges: @challenge_store,
          rpc: method.rpc,
          replay_store: replay_store,
          fee_payer: method.fee_payer,
          network: method.network,
          verifier: method.verifier,
          settlement_header: settlement_header
        )
      end

      # Handle one HTTP charge request. Returns either a payment-required
      # response (caller should emit 402) or a settlement (caller renders 200
      # and forwards the settlement headers).
      #
      # Pass `currency:` to charge in a currency other than the method's
      # default (e.g. an endpoint that accepts USDC by default but lets the
      # caller pay in USDT for this specific request).
      def charge(authorization, amount:, description: nil, external_id: nil, splits: nil, currency: nil)
        currency = currency.nil? ? method.currency : method.wire_currency(currency)
        details = method.method_details(currency: currency)
        if splits && !splits.empty?
          validate_splits!(splits, recipient: method.recipient)
          details = details.merge("splits" => splits)
        end

        request = ::PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(
          amount: amount.to_s,
          currency: currency,
          recipient: method.recipient,
          description: description,
          external_id: external_id,
          method_details: details
        )
        @handler.handle(authorization, request)
      end

      private

      MAX_SPLITS = 8

      # Validate splits at challenge issuance (audit #21 + #38) rather than
      # deferring every check to on-chain settlement. Enforces:
      #   - count <= MAX_SPLITS
      #   - each recipient parses as a 32-byte base58 pubkey
      #   - each amount parses as an integer, is > 0, and fits in u64
      #   - the aggregate does not overflow u64
      #   - no duplicate split recipients
      #   - (audit #38) no split whose recipient == the top-level recipient
      #     while ataCreationRequired is true — the fee-sponsored ATA
      #     recreate/drain shape.
      def validate_splits!(splits, recipient:)
        raise split_error("splits has more than #{MAX_SPLITS} entries") if splits.length > MAX_SPLITS

        seen = {}
        total = 0
        splits.each do |split|
          split_recipient = split["recipient"]
          raise split_error("split recipient is required") if split_recipient.to_s.empty?
          raise split_error("split recipient #{split_recipient.inspect} is not a valid base58 pubkey") unless valid_pubkey?(split_recipient)
          raise split_error("duplicate split recipient #{split_recipient}") if seen[split_recipient]
          seen[split_recipient] = true

          amount = split_amount(split)
          total += amount
          raise split_error("split amounts overflow u64") if total > ::PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest::U64_MAX

          if split_recipient == recipient && split["ataCreationRequired"] == true
            raise split_error("primary recipient must not appear in splits with ataCreationRequired: true")
          end
        end
      end

      def split_amount(split)
        value =
          begin
            Integer(split.fetch("amount"), 10)
          rescue KeyError, TypeError, ArgumentError
            raise split_error("split amount must be an integer string")
          end
        raise split_error("split amount must be greater than zero") unless value.positive?
        raise split_error("split amount exceeds the maximum u64 amount") if value > ::PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest::U64_MAX

        value
      end

      def valid_pubkey?(value)
        ::PayCore::Solana::Base58.decode(value.to_s).bytesize == 32
      rescue ArgumentError
        false
      end

      def split_error(message)
        ::PayKit::Protocols::Mpp::VerificationError.new(message, code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID)
      end

      # Reject empty/short HMAC secrets at boot (audit #24). Covers both the
      # explicit `secret_key:` argument and any value resolved from the
      # environment upstream (e.g. preflight's MPP_SECRET env path), since
      # both funnel through here. Counts bytes, not characters.
      def validate_secret_key!(secret_key)
        bytes = secret_key.to_s.bytesize
        return if bytes >= MIN_SECRET_KEY_BYTES

        raise ::PayKit::Protocols::Mpp::Error.new(
          "secret_key must be at least #{MIN_SECRET_KEY_BYTES} bytes of cryptographically-random data " \
          "(got #{bytes}); e.g. `openssl rand -base64 32`",
          code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID
        )
      end

      # Resolve the realm (audit #15). An explicit non-empty realm is honoured;
      # an explicit empty string is rejected (it would re-open the shared
      # namespace); when the caller passes the default sentinel we derive a
      # per-recipient realm so two servers sharing one secret but serving
      # different recipients land in different HMAC namespaces.
      def resolve_realm(realm, recipient)
        return derive_default_realm(recipient) if realm == ::PayKit::Protocols::Mpp::DEFAULT_REALM
        raise ::PayKit::Protocols::Mpp::Error.new("realm must not be empty", code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID) if realm.to_s.empty?

        realm
      end

      # Deterministically derive a human-friendly default realm from the
      # recipient pubkey: SHA-256 the recipient, take the first 4 bytes as a
      # big-endian u32 mod 10^8. Same recipient -> same realm (restart-safe);
      # different recipients -> different realms (closes cross-server replay).
      def derive_default_realm(recipient)
        digest = ::Digest::SHA256.digest(recipient.to_s)
        suffix = digest.byteslice(0, 4).unpack1("N") % 100_000_000
        "App Id - ##{suffix}"
      end

      # High-level Solana charge orchestrator: verify, settle, consume, receipt.
      # Not part of the public API. Drive this through `PayKit::Protocols::Mpp.create` + `Charge#charge`.
      class Handler
        SURFPOOL_BLOCKHASH_PREFIX = "SURFNETxSAFEHASH"
        DEFAULT_SETTLEMENT_HEADER = "x-payment-settlement-signature"

        attr_reader :fee_payer, :network, :settlement_header

        def initialize(challenges:, rpc:, replay_store:, fee_payer: nil, network: "mainnet",
          settlement_header: DEFAULT_SETTLEMENT_HEADER,
          verifier: ::PayKit::Protocols::Mpp::Protocol::Solana::Verifier.new,
          confirmation_attempts: 40, confirmation_delay: 0.25)
          @challenges = challenges
          @rpc = rpc
          @replay_store = replay_store
          @consumed_signatures = ::PayCore::ConsumedSignatures.new(replay_store)
          @fee_payer = fee_payer
          @network = network
          @settlement_header = settlement_header
          @verifier = verifier
          @confirmation_attempts = confirmation_attempts
          @confirmation_delay = confirmation_delay
        end

        # Public key of the server fee payer, when configured.
        def fee_payer_pubkey
          fee_payer&.public_key&.to_s
        end

        # Process one HTTP request and return a response object: a Challenge
        # (402), a SettlementPending (409, retry the same credential) or a
        # Settlement (200).
        #
        # Pull mode claims the transaction's locally derived signature once it
        # may have left the server, and records it as pending under this
        # challenge. A lost broadcast response or a confirmation timeout then
        # answers SettlementPending and keeps the claim, so the client is
        # never handed a fresh challenge it could pay a second time; a retry
        # of the same credential (even after its challenge expired) reconciles
        # the signature against the chain, never re-broadcasting it, and is
        # granted once. Only a preflight rejection leaves it unclaimed.
        def handle(authorization, request, now: Time.now.utc)
          return @challenges.payment_required_response(request) if authorization.nil? || authorization.empty?

          result = @challenges.verify_authorization_header(authorization, verifier: @verifier, expected_request: request, now: now)
          signature = if result.ok?
            settle_payload(result.credential, request)
          elsif result.expired?
            # An expired challenge never starts a payment; it may only finish
            # the one it already left pending.
            reconcile_expired(result.credential) ||
              (return @challenges.payment_required_response(request, reason: result.reason, code: result.code))
          else
            return @challenges.payment_required_response(request, reason: result.reason, code: result.code)
          end
          receipt = @challenges.create_receipt_header(challenge: result.challenge, reference: signature, external_id: request.external_id)
          ::PayKit::Protocols::Mpp::Settlement.new(
            signature: signature,
            receipt_header: receipt,
            headers: {
              ::PayKit::Protocols::Mpp::Protocol::Core::Headers::PAYMENT_RECEIPT => receipt,
              settlement_header => signature
            }
          )
        rescue SettlementInProgress => pending
          ::PayKit::Protocols::Mpp::SettlementPending.new(pending.message)
        rescue ArgumentError, ::PayKit::Protocols::Mpp::Error, ::PayCore::Solana::Rpc::RpcError, ::PayCore::Solana::Transaction::SigningError => error
          code = error.respond_to?(:code) ? error.code : nil
          @challenges.payment_required_response(request, reason: error.message, code: code)
        end

        # The payment may already be broadcast and is not resolved yet.
        class SettlementInProgress < StandardError; end

        # Prefix of the record binding a claimed, possibly broadcast signature
        # to the challenge that broadcast it: only that challenge reconciles it.
        # Namespaced to this SDK: another SDK's pending record under a
        # look-alike key must never be reconciled (and granted) here.
        PENDING_PREFIX = "pay-kit:ruby:charge-pending:"
        # Single-winner token for the one response a payment grants.
        GRANTED_PREFIX = "solana-charge:granted:"
        # A claimed signature refused for good (preflight, or already processed
        # elsewhere): the store cannot release it, so no retry reconciles it.
        REFUSED_PREFIX = "pay-kit:ruby:charge-refused:"

        private

        def settle_payload(credential, request)
          transaction = credential.payload["transaction"]
          return settle_pull(transaction, credential.challenge.id) if transaction.is_a?(String) && !transaction.empty?

          signature = credential.payload["signature"]
          raise ::PayKit::Protocols::Mpp::VerificationError, "missing transaction or signature payload" unless signature.is_a?(String) && !signature.empty?

          transaction_base64 = fetch_settled_transaction(signature)
          verification = @verifier.verify_transaction_payload(transaction_base64, request)
          raise ::PayKit::Protocols::Mpp::VerificationError, verification.reason unless verification.ok?

          consume_signature(signature)
          signature
        end

        # The transaction as this server broadcasts it (co-signed when it pays
        # the fee) and its locally derived signature.
        def signed_transaction(transaction_base64)
          transaction = ::PayCore::Solana::Transaction.from_base64(transaction_base64)
          transaction.sign_with(fee_payer) if fee_payer
          [transaction, transaction.to_base64, transaction.primary_signature]
        end

        def settle_pull(transaction_base64, challenge_id)
          transaction, signed_base64, local_signature = signed_transaction(transaction_base64)
          check_network_blockhash(transaction.message.recent_blockhash)
          # Every signature must verify before the signature is claimed or the
          # transaction sent. A forged one would otherwise name the charge: the
          # node refuses it without a preflight result, it is kept as possibly
          # sent, and a retry would reconcile on the status of whatever landed
          # transaction owns that signature.
          raise ::PayKit::Protocols::Mpp::VerificationError, "Transaction signature verification failed" unless transaction.signatures_verify?
          # Already claimed: a retry of a pending charge (reconcile it from the
          # chain, never broadcast again) or a replay.
          return reconcile(local_signature, challenge_id) if @consumed_signatures.claimed?(local_signature)

          simulation = simulate_transaction_with_retry(signed_base64)
          raise ::PayKit::Protocols::Mpp::VerificationError, "Simulation failed: #{simulation["err"].inspect}" unless simulation["err"].nil?

          # Claim the signature and bind it to this challenge before anything
          # is sent, so a payment that may land always has the record its
          # retry reconciles. Bound only after an ambiguous send, a store
          # failure would leave a claim with nothing to reconcile, and every
          # retry would refuse a payment that may have landed. A failure here
          # sends nothing.
          return reconcile(local_signature, challenge_id) unless claim_pending(local_signature, challenge_id)

          # Only a preflight rejection proves the node did not forward the
          # transaction. The store cannot release the claim, so the refusal
          # is recorded and the charge fails. Any other send error (a lost
          # response, a 5xx from a proxy that already forwarded it) leaves the
          # outcome unknown: the charge is reported as still settling.
          begin
            @rpc.send_raw_transaction(signed_base64)
          rescue ::PayCore::Solana::Rpc::RpcError => error
            if error.message.match?(/already (been )?processed/i)
              # It landed, yet this store held no claim on it: it was settled
              # somewhere this store cannot see. A replay.
              mark_refused(local_signature)
              raise ::PayKit::Protocols::Mpp::VerificationError.new("Transaction signature already consumed", code: ::PayCore::ErrorCodes::CODE_SIGNATURE_CONSUMED)
            end
            if error.is_a?(::PayCore::Solana::Rpc::PreflightRejection)
              mark_refused(local_signature)
              raise
            end

            raise SettlementInProgress,
              "Settlement of transaction #{local_signature} is in progress: broadcast outcome unknown " \
              "(#{error.message}); retry the same credential, do not pay again"
          end

          await_confirmation(local_signature)
          grant(local_signature)
        end

        def mark_refused(signature)
          @replay_store.put_if_absent("#{REFUSED_PREFIX}#{signature}", true)
        end

        # Claim `signature` and record it as pending under this challenge.
        # False when a concurrent presentation claimed it first: that one owns
        # it, and this one only reconciles (or is refused as a replay).
        def claim_pending(signature, challenge_id)
          return false unless @consumed_signatures.claim(signature)

          @replay_store.put_if_absent(pending_key(signature, challenge_id), true)
          true
        end

        def pending_key(signature, challenge_id)
          "#{PENDING_PREFIX}#{signature}:#{challenge_id}"
        end

        # Resolve a claimed signature from its on-chain status. Only the
        # challenge that left it pending may; anything else is a replay. Only
        # an explicit outcome resolves it: a missing status is never proof the
        # transaction did not execute, so it stays in progress.
        def reconcile(signature, challenge_id)
          unless @replay_store.key?(pending_key(signature, challenge_id))
            raise ::PayKit::Protocols::Mpp::VerificationError.new("Transaction signature already consumed", code: ::PayCore::ErrorCodes::CODE_SIGNATURE_CONSUMED)
          end
          raise ::PayKit::Protocols::Mpp::VerificationError, "Transaction #{signature} was refused and cannot settle" if @replay_store.key?("#{REFUSED_PREFIX}#{signature}")

          status = @rpc.signature_statuses([signature]).first
          if status.is_a?(Hash)
            raise ::PayKit::Protocols::Mpp::VerificationError, "Transaction #{signature} failed: #{status["err"].inspect}" unless status["err"].nil?
            return grant(signature) if ["confirmed", "finalized"].include?(status["confirmationStatus"])
          end
          raise SettlementInProgress,
            "Transaction #{signature} is not confirmed yet; retry the same credential, do not pay again"
        rescue ::PayCore::Solana::Rpc::RpcError => error
          raise SettlementInProgress,
            "Transaction #{signature} status unavailable (#{error.message}); retry the same credential, do not pay again"
        end

        # The pending charge an expired credential's challenge left behind,
        # reconciled from the chain; nil when that challenge has none.
        def reconcile_expired(credential)
          transaction = credential&.payload&.fetch("transaction", nil)
          return nil unless transaction.is_a?(String) && !transaction.empty?

          _, _, signature = begin
            signed_transaction(transaction)
          rescue ArgumentError, ::PayKit::Protocols::Mpp::Error, ::PayCore::Solana::Transaction::SigningError
            return nil
          end
          return nil unless @replay_store.key?(pending_key(signature, credential.challenge.id))

          reconcile(signature, credential.challenge.id)
        end

        # One response per payment: only the first confirmation of a
        # signature, on any path, is granted.
        def grant(signature)
          return signature if @replay_store.put_if_absent("#{GRANTED_PREFIX}#{signature}", true)

          raise ::PayKit::Protocols::Mpp::VerificationError.new("Transaction signature already consumed", code: ::PayCore::ErrorCodes::CODE_SIGNATURE_CONSUMED)
        end

        def fetch_settled_transaction(signature)
          @confirmation_attempts.times do
            response = @rpc.transaction_base64(signature)
            if response.nil?
              sleep @confirmation_delay
              next
            end
            meta = response["meta"]
            raise ::PayKit::Protocols::Mpp::VerificationError, "getTransaction response is missing transaction metadata" unless meta.is_a?(Hash)
            raise ::PayKit::Protocols::Mpp::VerificationError, "Transaction #{signature} failed: #{meta["err"].inspect}" unless meta["err"].nil?

            wire = response["transaction"]
            return wire[0] if wire.is_a?(Array) && wire[0].is_a?(String) && !wire[0].empty?

            raise ::PayKit::Protocols::Mpp::VerificationError, "getTransaction response is missing base64 transaction"
          end
          raise ::PayKit::Protocols::Mpp::VerificationError, "Timed out fetching transaction #{signature}"
        end

        # A status that never surfaces is not proof the transaction did not
        # execute (the node may lag or lack its history): the charge stays
        # pending for the same credential to reconcile.
        def await_confirmation(signature)
          @confirmation_attempts.times do
            status = begin
              @rpc.signature_statuses([signature]).first
            rescue ::PayCore::Solana::Rpc::RpcError
              nil
            end
            if status.is_a?(Hash)
              raise ::PayKit::Protocols::Mpp::VerificationError, "Transaction #{signature} failed: #{status["err"].inspect}" unless status["err"].nil?
              return if ["confirmed", "finalized"].include?(status["confirmationStatus"])
            end
            sleep @confirmation_delay
          end
          raise SettlementInProgress,
            "Timed out waiting for transaction #{signature}; it may still land, retry the same credential, do not pay again"
        end

        def simulate_transaction_with_retry(transaction_base64)
          last = nil
          3.times do
            last = @rpc.simulate_transaction(transaction_base64)
            return last if last["err"].nil?

            sleep @confirmation_delay
          end
          last
        end

        # Claimed in the ledger shared with x402 exact, so a payment settled
        # through either protocol cannot authorize a second request through
        # the other.
        def consume_signature(signature)
          inserted = @consumed_signatures.claim(signature)
          raise ::PayKit::Protocols::Mpp::VerificationError.new("Transaction signature already consumed", code: ::PayCore::ErrorCodes::CODE_SIGNATURE_CONSUMED) unless inserted
        end

        def check_network_blockhash(blockhash)
          return unless blockhash.start_with?(SURFPOOL_BLOCKHASH_PREFIX)
          return if network == "localnet"

          raise ::PayKit::Protocols::Mpp::VerificationError.new("Signed against localnet but the server expects #{network}. Switch your client RPC to #{network} and re-sign.", code: ::PayCore::ErrorCodes::CODE_WRONG_NETWORK)
        end
      end
    end
  end
end
