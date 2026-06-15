# frozen_string_literal: true

require "base64"
require "digest"

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
        currency ||= method.currency
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

        # Process one HTTP request and return a response object.
        #
        # The settlement order is: broadcast (pull) or fetch (push), then
        # consume_signature, then await_confirmation (pull only). The consume
        # call sits between broadcast and confirmation polling on purpose so
        # that a confirmation timeout or server crash after the transaction has
        # already landed on chain cannot be replayed against the same
        # credential. See PR #85 Greptile P1 and audit gap G05.
        def handle(authorization, request)
          return @challenges.payment_required_response(request) if authorization.nil? || authorization.empty?

          result = @challenges.verify_authorization_header(authorization, verifier: @verifier, expected_request: request)
          return @challenges.payment_required_response(request, reason: result.reason, code: result.code) unless result.ok?

          signature = settle_payload(result.credential, request)
          consume_signature(signature)
          await_settlement(result.credential, signature)
          receipt = @challenges.create_receipt_header(challenge: result.challenge, reference: signature, external_id: request.external_id)
          ::PayKit::Protocols::Mpp::Settlement.new(
            signature: signature,
            receipt_header: receipt,
            headers: {
              ::PayKit::Protocols::Mpp::Protocol::Core::Headers::PAYMENT_RECEIPT => receipt,
              settlement_header => signature
            }
          )
        rescue ArgumentError, ::PayKit::Protocols::Mpp::Error, ::PayCore::Solana::Rpc::RpcError, ::PayCore::Solana::Transaction::SigningError => error
          code = error.respond_to?(:code) ? error.code : nil
          @challenges.payment_required_response(request, reason: error.message, code: code)
        end

        private

        def settle_payload(credential, request)
          transaction = credential.payload["transaction"]
          return settle_pull(transaction) if transaction.is_a?(String) && !transaction.empty?

          signature = credential.payload["signature"]
          raise ::PayKit::Protocols::Mpp::VerificationError, "missing transaction or signature payload" unless signature.is_a?(String) && !signature.empty?

          transaction_base64 = fetch_settled_transaction(signature)
          verification = @verifier.verify_transaction_payload(transaction_base64, request)
          raise ::PayKit::Protocols::Mpp::VerificationError, verification.reason unless verification.ok?

          signature
        end

        def settle_pull(transaction_base64)
          transaction = ::PayCore::Solana::Transaction.from_base64(transaction_base64)
          check_network_blockhash(transaction.message.recent_blockhash)
          transaction.sign_with(fee_payer) if fee_payer
          signed_base64 = transaction.to_base64
          simulation = simulate_transaction_with_retry(signed_base64)
          raise ::PayKit::Protocols::Mpp::VerificationError, "Simulation failed: #{simulation["err"].inspect}" unless simulation["err"].nil?

          @rpc.send_raw_transaction(signed_base64)
        end

        # await_confirmation only runs on the pull path; push mode already
        # fetched a confirmed transaction in settle_payload.
        def await_settlement(credential, signature)
          transaction = credential.payload["transaction"]
          return unless transaction.is_a?(String) && !transaction.empty?

          await_confirmation(signature)
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

        def await_confirmation(signature)
          @confirmation_attempts.times do
            status = @rpc.signature_statuses([signature]).first
            if status.is_a?(Hash)
              raise ::PayKit::Protocols::Mpp::VerificationError, "Transaction #{signature} failed: #{status["err"].inspect}" unless status["err"].nil?
              return if ["confirmed", "finalized"].include?(status["confirmationStatus"])
            end
            sleep @confirmation_delay
          end
          raise ::PayKit::Protocols::Mpp::VerificationError, "Timed out waiting for transaction #{signature}"
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

        def consume_signature(signature)
          key = "solana-charge:consumed:#{signature}"
          inserted = @replay_store.put_if_absent(key, true)
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
