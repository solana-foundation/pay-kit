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

  # Returned by Server#charge when the credential's payment was (or may have
  # been) broadcast and is not resolved yet. It is a retryable 409 with no
  # challenge: a client handed a fresh challenge could pay it while the
  # original lands, and pay twice. The client retries the same credential,
  # which reconciles the pending signature and returns the receipt once.
  class SettlementPending
    STATUS = 409

    attr_reader :headers, :body

    def initialize(detail)
      @headers = {
        "cache-control" => "no-store",
        "content-type" => "application/problem+json",
        "retry-after" => "1"
      }
      @body = {
        "type" => "https://paymentauth.org/problems/settlement-in-progress",
        "title" => "Settlement Already In Progress",
        "status" => STATUS,
        "code" => ::PayCore::ErrorCodes::CODE_SETTLEMENT_IN_PROGRESS,
        "detail" => detail
      }
    end

    def status
      STATUS
    end

    def reason
      @body["detail"]
    end
  end
end
