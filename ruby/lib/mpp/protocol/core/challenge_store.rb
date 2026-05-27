# frozen_string_literal: true

require "pay_core/error_codes"

module Mpp
  module Protocol
    module Core
      # Low-level charge challenge issuer and credential verifier.
      # Not part of the public API.
      class ChallengeStore
        DEFAULT_EXPIRES_SECONDS = 300

        attr_reader :secret_key, :realm, :blockhash_provider, :default_expires_seconds

        def initialize(secret_key:, realm: "MPP Payment", blockhash_provider: nil,
          default_expires_seconds: DEFAULT_EXPIRES_SECONDS)
          @secret_key = secret_key
          @realm = realm
          @blockhash_provider = blockhash_provider
          @default_expires_seconds = default_expires_seconds
        end

        # Create an MPP charge challenge. When `expires:` is omitted the
        # store's `default_expires_seconds` is applied freshly per call
        # so the timestamp always reflects "now + N", not the moment the
        # store was constructed.
        def create_challenge(request, expires: nil, description: nil)
          Core::Challenge.with_secret(
            secret_key: secret_key,
            realm: realm,
            method: "solana",
            intent: "charge",
            request: request_payload(request),
            expires: expires || Expires.seconds(default_expires_seconds),
            description: description
          )
        end

        # Create the `WWW-Authenticate` header value for a charge request.
        def create_challenge_header(request, expires: nil, description: nil)
          ::Mpp::Protocol::Core::Headers.format_www_authenticate(create_challenge(request, expires: expires, description: description))
        end

        # Return a 402 response for a charge request.
        #
        # When `reason` is nil the body is the legacy unauthenticated shape
        # `{error: payment_required}` and no code is attached: the request has
        # not been verified yet so there is nothing to classify.
        #
        # When `reason` is present the body carries:
        # - `code`: canonical L6 code (`PayCore::ErrorCodes::CODE_*`)
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
            canonical = code || ::PayCore::ErrorCodes.canonical_code(reason)
            {"code" => canonical, "error" => canonical, "message" => reason}
          end
          ::Mpp::Challenge.new(www_authenticate: header, body: body, reason: reason)
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

          return Protocol::Solana::VerificationResult.failure("challenge verification failed", code: ::PayCore::ErrorCodes::CODE_CHALLENGE_VERIFICATION_FAILED) unless challenge.verify?(secret_key)
          return Protocol::Solana::VerificationResult.failure("challenge expired", code: ::PayCore::ErrorCodes::CODE_CHALLENGE_EXPIRED) if challenge.expired?(now: now)

          result = verify_pinned_fields(challenge, expected_request)
          return result unless result.ok?

          decoded = Intents::ChargeRequest.from_h(challenge.decode_request)
          result = verify_expected(decoded, expected_request)
          return result unless result.ok?

          result = verifier.verify(credential, challenge, expected_request: expected_request)
          return result unless result.ok?

          Protocol::Solana::VerificationResult.success(reference: result.reference, credential: credential, challenge: challenge)
        rescue KeyError, ArgumentError, Error => error
          code = error.respond_to?(:code) ? error.code : nil
          Protocol::Solana::VerificationResult.failure(error.message, code: code)
        end

        # Create a receipt header for a settled on-chain signature.
        def create_receipt_header(challenge:, reference:, external_id: nil)
          receipt = Core::Receipt.success(
            method: "solana",
            reference: reference,
            challenge_id: challenge.id,
            external_id: external_id
          )
          ::Mpp::Protocol::Core::Headers.format_receipt(receipt)
        end

        private

        def verify_pinned_fields(challenge, expected)
          return Protocol::Solana::VerificationResult.failure("Credential method does not match this server", code: ::PayCore::ErrorCodes::CODE_CHALLENGE_ROUTE_MISMATCH) unless challenge.method == "solana"
          return Protocol::Solana::VerificationResult.failure("Credential intent is not a charge", code: ::PayCore::ErrorCodes::CODE_CHALLENGE_ROUTE_MISMATCH) unless challenge.intent.casecmp("charge").zero?
          return Protocol::Solana::VerificationResult.failure("Credential realm does not match this server", code: ::PayCore::ErrorCodes::CODE_CHALLENGE_ROUTE_MISMATCH) unless challenge.realm == realm
          return Protocol::Solana::VerificationResult.failure("Endpoint currency is required", code: ::PayCore::ErrorCodes::CODE_PAYMENT_INVALID) if expected.currency.to_s.empty?
          return Protocol::Solana::VerificationResult.failure("Credential recipient does not match this server", code: ::PayCore::ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) if expected.recipient.to_s.empty?

          Protocol::Solana::VerificationResult.success
        end

        def verify_expected(decoded, expected)
          return Protocol::Solana::VerificationResult.failure("Amount mismatch: credential has #{decoded.amount} but endpoint expects #{expected.amount}", code: ::PayCore::ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless decoded.amount == expected.amount
          return Protocol::Solana::VerificationResult.failure("Currency mismatch: credential has #{decoded.currency} but endpoint expects #{expected.currency}", code: ::PayCore::ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless decoded.currency == expected.currency
          return Protocol::Solana::VerificationResult.failure("Recipient mismatch", code: ::PayCore::ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless decoded.recipient == expected.recipient
          return Protocol::Solana::VerificationResult.failure("Method details mismatch", code: ::PayCore::ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH) unless comparable_method_details(decoded.method_details) == comparable_method_details(expected.method_details)

          Protocol::Solana::VerificationResult.success
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
end
