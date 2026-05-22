# frozen_string_literal: true

module SolanaMpp
  module Server
    # HTTP 402 response returned when payment is required or invalid.
    class PaymentRequiredResponse
      attr_reader :status, :headers, :body

      def initialize(headers:, body: {"error" => "payment_required"})
        @status = 402
        @headers = headers
        @body = body
      end
    end

    # HTTP 200 response returned after successful charge settlement.
    class ChargeSettlement
      attr_reader :status, :headers, :body, :signature, :receipt_header

      def initialize(headers:, body:, signature:, receipt_header:)
        @status = 200
        @headers = headers
        @body = body
        @signature = signature
        @receipt_header = receipt_header
      end
    end
  end
end
