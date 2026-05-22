# frozen_string_literal: true

require "base64"

module Mpp
  module Internal
    # High-level Solana charge orchestrator: verify, settle, consume, receipt.
    # Not part of the public API — drive this through Mpp.create + Server#charge.
    class Handler
      SURFPOOL_BLOCKHASH_PREFIX = "SURFNETxSAFEHASH"
      DEFAULT_SETTLEMENT_HEADER = "x-payment-settlement-signature"

      attr_reader :fee_payer, :network, :settlement_header

      def initialize(challenges:, rpc:, replay_store:, fee_payer: nil, network: "mainnet", settlement_header: DEFAULT_SETTLEMENT_HEADER, verifier: Methods::Solana::Verifier.new, confirmation_attempts: 40, confirmation_delay: 0.25)
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
      def handle(authorization, request)
        return @challenges.payment_required_response(request) if authorization.nil? || authorization.empty?

        result = @challenges.verify_authorization_header(authorization, verifier: @verifier, expected_request: request)
        return @challenges.payment_required_response(request, reason: result.reason) unless result.ok?

        signature = settle_payload(result.credential, request)
        consume_signature(signature)
        receipt = @challenges.create_receipt_header(challenge: result.challenge, reference: signature, external_id: request.external_id)
        Settlement.new(
          signature: signature,
          receipt_header: receipt,
          headers: {
            Core::Headers::PAYMENT_RECEIPT => receipt,
            settlement_header => signature
          }
        )
      rescue ArgumentError, Error => error
        @challenges.payment_required_response(request, reason: error.message)
      end

      private

      def settle_payload(credential, request)
        transaction = credential.payload["transaction"]
        return settle_pull(transaction) if transaction.is_a?(String) && !transaction.empty?

        signature = credential.payload["signature"]
        raise VerificationError, "missing transaction or signature payload" unless signature.is_a?(String) && !signature.empty?

        transaction_base64 = fetch_settled_transaction(signature)
        verification = @verifier.verify_transaction_payload(transaction_base64, request)
        raise VerificationError, verification.reason unless verification.ok?

        signature
      end

      def settle_pull(transaction_base64)
        transaction = Methods::Solana::Transaction.from_base64(transaction_base64)
        check_network_blockhash(transaction.message.recent_blockhash)
        transaction.sign_with(fee_payer) if fee_payer
        signed_base64 = transaction.to_base64
        simulation = simulate_transaction_with_retry(signed_base64)
        raise VerificationError, "Simulation failed: #{simulation["err"].inspect}" unless simulation["err"].nil?

        signature = @rpc.send_raw_transaction(signed_base64)
        await_confirmation(signature)
        signature
      end

      def fetch_settled_transaction(signature)
        @confirmation_attempts.times do
          response = @rpc.transaction_base64(signature)
          if response.nil?
            sleep @confirmation_delay
            next
          end
          meta = response["meta"]
          raise VerificationError, "getTransaction response is missing transaction metadata" unless meta.is_a?(Hash)
          raise VerificationError, "Transaction #{signature} failed: #{meta["err"].inspect}" unless meta["err"].nil?

          wire = response["transaction"]
          return wire[0] if wire.is_a?(Array) && wire[0].is_a?(String) && !wire[0].empty?

          raise VerificationError, "getTransaction response is missing base64 transaction"
        end
        raise VerificationError, "Timed out fetching transaction #{signature}"
      end

      def await_confirmation(signature)
        @confirmation_attempts.times do
          status = @rpc.signature_statuses([signature]).first
          if status.is_a?(Hash)
            raise VerificationError, "Transaction #{signature} failed: #{status["err"].inspect}" unless status["err"].nil?
            return if ["confirmed", "finalized"].include?(status["confirmationStatus"])
          end
          sleep @confirmation_delay
        end
        raise VerificationError, "Timed out waiting for transaction #{signature}"
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
        raise VerificationError, "Transaction signature already consumed" unless inserted
      end

      def check_network_blockhash(blockhash)
        return unless blockhash.start_with?(SURFPOOL_BLOCKHASH_PREFIX)
        return if network == "localnet"

        raise VerificationError, "Signed against localnet but the server expects #{network}. Switch your client RPC to #{network} and re-sign."
      end
    end
  end
end
