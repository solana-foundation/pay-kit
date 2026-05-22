# frozen_string_literal: true

module SolanaMpp
  module Server
    # Result returned by lower-level credential verifiers.
    class VerificationResult
      attr_reader :reference, :reason, :credential, :challenge

      def initialize(ok:, reference: nil, reason: nil, credential: nil, challenge: nil)
        @ok = ok
        @reference = reference
        @reason = reason
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

      # Create a failed verification result.
      def self.failure(reason)
        new(ok: false, reason: reason)
      end
    end
  end
end
