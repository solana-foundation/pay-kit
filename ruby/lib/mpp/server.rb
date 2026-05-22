# frozen_string_literal: true

module Mpp
  # Server-side namespace. Holds the instance returned by Mpp.create plus
  # the Rack middleware and challenge response decorator.
  module Server
    # User-facing server. Build one with Mpp.create(method:, ...).
    #
    #   server = Mpp.create(method: ...)
    #   result = server.charge(authorization_header, amount: "1000", description: "Paid")
    #   case result
    #   when Mpp::Challenge  then # render 402
    #   when Mpp::Settlement then # render 200, include result.receipt_header
    #   end
    class Instance
      attr_reader :method, :realm

      def initialize(method:, secret_key:, realm:, replay_store:, settlement_header: Internal::Handler::DEFAULT_SETTLEMENT_HEADER)
        @method = method
        @realm = realm
        @challenge_store = Internal::ChallengeStore.new(
          secret_key: secret_key,
          realm: realm
        )
        @handler = Internal::Handler.new(
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

        request = Intent::ChargeRequest.new(
          amount: amount.to_s,
          currency: currency,
          recipient: method.recipient,
          description: description,
          external_id: external_id,
          method_details: details
        )
        @handler.handle(authorization, request)
      end
    end
  end
end
