# frozen_string_literal: true

require "time"

module Mpp
  module Core
    # Payment receipt returned after successful settlement.
    class Receipt
      attr_reader :status, :method, :reference, :challenge_id, :external_id, :timestamp

      def initialize(status:, method:, reference:, challenge_id:, external_id: nil, timestamp: Time.now.utc.iso8601)
        @status = status.to_s
        @method = method.to_s
        @reference = reference.to_s
        @challenge_id = challenge_id.to_s
        @external_id = external_id
        @timestamp = timestamp
      end

      # Create a successful payment receipt.
      def self.success(method:, reference:, challenge_id:, external_id: nil)
        new(status: "success", method: method, reference: reference, challenge_id: challenge_id, external_id: external_id)
      end

      # Serialize to the wire receipt shape.
      def to_h
        value = {
          "status" => status,
          "method" => method,
          "reference" => reference,
          "challengeId" => challenge_id,
          "timestamp" => timestamp
        }
        value["externalId"] = external_id unless external_id.nil?
        value
      end
    end
  end
end
