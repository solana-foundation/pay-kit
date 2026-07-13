# frozen_string_literal: true

require_relative "../../../test_helper"

require "base64"
require "json"
require "open3"
require "rbconfig"

class ConformanceX402AmountTest < Minitest::Test
  CONFORMANCE_RUNNER = File.expand_path("../../../../exe/conformance", __dir__)
  DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
  RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
  ASSET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

  def test_conformance_accepts_matching_amount_aliases_and_omission
    [{"amount" => "1000"}, {"maxAmountRequired" => "1000"}, {}].each do |amount_fields|
      assert_equal "accept", run_vector(amount_fields).fetch("outcome")
    end
  end

  def test_conformance_rejects_every_present_drifting_amount_alias
    [{"amount" => "999"}, {"maxAmountRequired" => "999"},
      {"amount" => "1000", "maxAmountRequired" => "999"}].each do |amount_fields|
      result = run_vector(amount_fields)

      assert_equal "reject", result.fetch("outcome")
      assert_equal "amount-mismatch", result.fetch("rejectCode")
    end
  end

  private

  def run_vector(amount_fields)
    accepted = {
      "network" => DEVNET,
      "asset" => ASSET,
      "payTo" => RECIPIENT
    }.merge(amount_fields)
    header = Base64.strict_encode64(JSON.generate({
      "x402Version" => 2,
      "accepted" => accepted,
      "payload" => {"transaction" => "AA=="}
    }))
    vector = {
      "id" => "ruby-x402-accepted-amount",
      "intent" => "x402-exact",
      "mode" => "verify-transaction",
      "input" => {
        "x402PaymentHeader" => header,
        "x402ServerNetwork" => "devnet",
        "x402ServerRecipient" => RECIPIENT,
        "x402ServerCurrency" => ASSET,
        "x402ServerAmount" => "1000"
      }
    }

    output, error, status = Open3.capture3(
      RbConfig.ruby,
      CONFORMANCE_RUNNER,
      stdin_data: JSON.generate(vector)
    )
    assert status.success?, error

    JSON.parse(output)
  end
end
