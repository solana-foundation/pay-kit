# frozen_string_literal: true

require "base64"

require "pay_core/error_codes"
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
      attr_reader :method, :realm

      def initialize(method:, secret_key:, realm:, replay_store:,
        settlement_header: Handler::DEFAULT_SETTLEMENT_HEADER,
        expires_in: ::PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore::DEFAULT_EXPIRES_SECONDS)
        @method = method
        @realm = realm
        @challenge_store = ::PayKit::Protocols::Mpp::Protocol::Core::ChallengeStore.new(
          secret_key: secret_key,
          realm: realm,
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
        details = details.merge("splits" => splits) if splits && !splits.empty?

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
