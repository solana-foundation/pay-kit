# frozen_string_literal: true

module Mpp
  module Internal
    # Low-level charge challenge issuer and credential verifier.
    # Not part of the public API.
    class ChallengeStore
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
      #
      # When `reason` is nil the body is the legacy unauthenticated shape
      # `{error: payment_required}` and no code is attached: the request has
      # not been verified yet so there is nothing to classify.
      #
      # When `reason` is present the body carries:
      # - `code`: canonical L6 code (`Mpp::ErrorCodes::CODE_*`)
      # - `error`: alias of `code` for backward compatibility
      # - `message`: human-readable reason string
      #
      # `code` argument forces a specific canonical code; without it the
      # classifier maps the reason string to a canonical code.
      def payment_required_response(request, reason: nil, code: nil)
        header = create_challenge_header(request, description: request.description)
        body = if reason.nil?
          {"error" => "payment_required"}
        else
          canonical = code || ErrorCodes.canonical_code(reason)
          {"code" => canonical, "error" => canonical, "message" => reason}
        end
        Challenge.new(www_authenticate: header, body: body, reason: reason)
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

        return Methods::Solana::VerificationResult.failure("challenge verification failed", code: ErrorCodes::CODE_CHALLENGE_VERIFICATION_FAILED) unless challenge.verify?(secret_key)
        return Methods::Solana::VerificationResult.failure("challenge expired", code: ErrorCodes::CODE_CHALLENGE_EXPIRED) if challenge.expired?(now: now)

        result = verify_pinned_fields(challenge, expected_request)
        return result unless result.ok?

        decoded = Intent::ChargeRequest.from_h(challenge.decode_request)
        result = verify_expected(decoded, expected_request)
        return result unless result.ok?

        result = verifier.verify(credential, challenge, expected_request: expected_request)
        return result unless result.ok?

        Methods::Solana::VerificationResult.success(reference: result.reference, credential: credential, challenge: challenge)
      rescue KeyError, ArgumentError, Error => error
        code = error.respond_to?(:code) ? error.code : nil
        Methods::Solana::VerificationResult.failure(error.message, code: code)
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
        return Methods::Solana::VerificationResult.failure("Credential method does not match this server", code: ErrorCodes::CODE_CHALLENGE_ROUTE_MISMATCH) unless challenge.method == "solana"
        return Methods::Solana::VerificationResult.failure("Credential intent is not a charge", code: ErrorCodes::CODE_CHALLENGE_ROUTE_MISMATCH) unless challenge.intent.casecmp("charge").zero?
        return Methods::Solana::VerificationResult.failure("Credential realm does not match this server", code: ErrorCodes::CODE_CHALLENGE_ROUTE_MISMATCH) unless challenge.realm == realm
        return Methods::Solana::VerificationResult.failure("Endpoint currency is required", code: ErrorCodes::CODE_PAYMENT_INVALID) if expected.currency.to_s.empty?
        return Methods::Solana::VerificationResult.failure("Credential recipient does not match this server", code: ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) if expected.recipient.to_s.empty?

        Methods::Solana::VerificationResult.success
      end

      def verify_expected(decoded, expected)
        return Methods::Solana::VerificationResult.failure("Amount mismatch: credential has #{decoded.amount} but endpoint expects #{expected.amount}", code: ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless decoded.amount == expected.amount
        return Methods::Solana::VerificationResult.failure("Currency mismatch: credential has #{decoded.currency} but endpoint expects #{expected.currency}", code: ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless decoded.currency == expected.currency
        return Methods::Solana::VerificationResult.failure("Recipient mismatch", code: ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless decoded.recipient == expected.recipient
        return Methods::Solana::VerificationResult.failure("Method details mismatch", code: ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless comparable_method_details(decoded.method_details) == comparable_method_details(expected.method_details)

        Methods::Solana::VerificationResult.success
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
