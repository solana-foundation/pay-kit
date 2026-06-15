# frozen_string_literal: true

require "time"

module PayKit::Protocols::Mpp
  module Protocol
    module Core
      # Payment receipt returned after successful settlement.
      class Receipt
        attr_reader :status, :method, :reference, :challenge_id, :external_id, :timestamp

        def initialize(status:, method:, reference:, challenge_id: nil, external_id: nil, timestamp: Time.now.utc.iso8601)
          @status = status.to_s
          @method = method.to_s
          @reference = reference.to_s
          # `challengeId` is advisory and absent from the canonical receipt
          # shape; keep it only when a non-empty value is supplied.
          @challenge_id = (challenge_id.nil? || challenge_id.to_s.empty?) ? nil : challenge_id.to_s
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
            "timestamp" => timestamp
          }
          value["challengeId"] = challenge_id unless challenge_id.nil?
          value["externalId"] = external_id unless external_id.nil?
          value
        end
      end
    end
  end
end
