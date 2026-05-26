# frozen_string_literal: true

module Mpp
  module Protocol
    module Solana
      # Result returned by lower-level credential verifiers.
      class VerificationResult
        attr_reader :reference, :reason, :code, :credential, :challenge

        def initialize(ok:, reference: nil, reason: nil, code: nil, credential: nil, challenge: nil)
          @ok = ok
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
