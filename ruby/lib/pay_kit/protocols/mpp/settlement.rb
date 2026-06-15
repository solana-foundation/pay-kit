# frozen_string_literal: true

module PayKit::Protocols::Mpp
  # Returned by Server#charge after payment has been verified and settled
  # on-chain. Render your normal 200 response and forward Settlement#headers
  # so the client receives the receipt and the on-chain signature.
  class Settlement
    STATUS = 200

    attr_reader :signature, :receipt_header, :headers

    def initialize(signature:, receipt_header:, headers:)
      @signature = signature
      @receipt_header = receipt_header
      @headers = headers
    end

    def status
      STATUS
    end
  end
end
