# frozen_string_literal: true

module SolanaMpp
  module Server
    # Low-level charge challenge issuer and credential verifier.
    class ChargeServer
      attr_reader :secret_key, :realm, :blockhash_provider

      def initialize(secret_key:, realm: "MPP Payment", blockhash_provider: nil)
        @secret_key = secret_key
        @realm = realm
        @blockhash_provider = blockhash_provider
      end

      # Create an MPP charge challenge.
      def create_challenge(request, expires: Expires.minutes(5), description: nil)
        Core::Challenge.with_secret(
          secret_key: secret_key,
          realm: realm,
          method: "solana",
          intent: "charge",
          request: request_payload(request),
          expires: expires,
          description: description
        )
      end

      # Create the `WWW-Authenticate` header value for a charge request.
      def create_challenge_header(request, expires: Expires.minutes(5), description: nil)
        Core::Headers.format_www_authenticate(create_challenge(request, expires: expires, description: description))
      end

      # Return a 402 response for a charge request.
      def payment_required_response(request, reason: nil)
        header = create_challenge_header(request, description: request.description)
        body = reason.nil? ? {"error" => "payment_required"} : {"error" => "payment_invalid", "message" => reason}
        PaymentRequiredResponse.new(headers: {Core::Headers::WWW_AUTHENTICATE => header}, body: body)
      end

      # Verify a Payment authorization header.
      def verify_authorization_header(header, verifier:, expected_request:, now: Time.now.utc)
        credential = Core::Credential.from_authorization_header(header)
        challenge = Core::Challenge.new(
          id: credential.challenge.id,
          realm: credential.challenge.realm,
          method: credential.challenge.method,
          intent: credential.challenge.intent,
          request: credential.challenge.request,
          expires: credential.challenge.expires,
          digest: credential.challenge.digest,
          opaque: credential.challenge.opaque
        )

        return VerificationResult.failure("challenge verification failed") unless challenge.verify?(secret_key)
        return VerificationResult.failure("challenge expired") if challenge.expired?(now: now)

        result = verify_pinned_fields(challenge, expected_request)
        return result unless result.ok?

        decoded = Intent::ChargeRequest.from_h(challenge.decode_request)
        result = verify_expected(decoded, expected_request)
        return result unless result.ok?

        result = verifier.verify(credential, challenge, expected_request: expected_request)
        return result unless result.ok?

        VerificationResult.success(reference: result.reference, credential: credential, challenge: challenge)
      rescue KeyError, ArgumentError, Error => error
        VerificationResult.failure(error.message)
      end

      # Create a receipt header for a settled on-chain signature.
      def create_receipt_header(challenge:, reference:, external_id: nil)
        receipt = Core::Receipt.success(
          method: "solana",
          reference: reference,
          challenge_id: challenge.id,
          external_id: external_id
        )
        Core::Headers.format_receipt(receipt)
      end

      private

      def verify_pinned_fields(challenge, expected)
        return VerificationResult.failure("Credential method does not match this server") unless challenge.method == "solana"
        return VerificationResult.failure("Credential intent is not a charge") unless challenge.intent.casecmp("charge").zero?
        return VerificationResult.failure("Credential realm does not match this server") unless challenge.realm == realm
        return VerificationResult.failure("Endpoint currency is required") if expected.currency.to_s.empty?
        return VerificationResult.failure("Credential recipient does not match this server") if expected.recipient.to_s.empty?

        VerificationResult.success
      end

      def verify_expected(decoded, expected)
        return VerificationResult.failure("Amount mismatch: credential has #{decoded.amount} but endpoint expects #{expected.amount}") unless decoded.amount == expected.amount
        return VerificationResult.failure("Currency mismatch: credential has #{decoded.currency} but endpoint expects #{expected.currency}") unless decoded.currency == expected.currency
        return VerificationResult.failure("Recipient mismatch") unless decoded.recipient == expected.recipient
        return VerificationResult.failure("Method details mismatch") unless comparable_method_details(decoded.method_details) == comparable_method_details(expected.method_details)

        VerificationResult.success
      end

      def request_payload(request)
        payload = request.to_h
        return payload unless blockhash_provider

        details = (payload["methodDetails"] || {}).dup
        details["recentBlockhash"] = blockhash_provider.call if details["recentBlockhash"].to_s.empty?
        payload.merge("methodDetails" => details)
      end

      def comparable_method_details(details)
        (details || {}).except("recentBlockhash")
      end
    end
  end
end
