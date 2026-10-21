# frozen_string_literal: true

module PayKit::Protocols::Mpp
  module Protocol
    module Solana
      # Result returned by lower-level credential verifiers.
      class VerificationResult
        attr_reader :reference, :reason, :code, :credential, :challenge

        def initialize(ok:, reference: nil, reason: nil, code: nil, credential: nil, challenge: nil, expired: false)
          @ok = ok
          @expired = expired
          @reference = reference
          @reason = reason
          @code = code
          @credential = credential
          @challenge = challenge
        end

        # Return true when verification succeeded.
        def ok?
          @ok
        end

        # True for an authentic credential whose challenge expired. It never
        # authorizes a new payment; the caller may only reconcile a charge that
        # challenge already left pending.
        def expired?
          @expired
        end

        # A failed result for an authentic credential whose challenge expired,
        # every other check having passed. Carries the credential and challenge.
        def self.expired(credential:, challenge:)
          new(ok: false, reason: "challenge expired", code: ::PayCore::ErrorCodes::CODE_CHALLENGE_EXPIRED,
            credential: credential, challenge: challenge, expired: true)
        end

        # Create a successful verification result.
        def self.success(reference: nil, credential: nil, challenge: nil)
          new(ok: true, reference: reference, credential: credential, challenge: challenge)
        end

        # Create a failed verification result. The optional `code` carries the
        # canonical L6 error code (see PayCore::ErrorCodes); when nil, the response
        # builder classifies the reason string into a canonical code.
        def self.failure(reason, code: nil)
          new(ok: false, reason: reason, code: code)
        end
      end
    end
  end
end
