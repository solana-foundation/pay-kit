# frozen_string_literal: true

require_relative "test_helper"

class ChargeRequestTest < Minitest::Test
  def test_serializes_camel_case_wire_fields
    request = Mpp::Intent::ChargeRequest.new(
      amount: "1000",
      currency: "USDC",
      recipient: "recipient",
      description: "API call",
      external_id: "order-001",
      method_details: {"network" => "localnet"}
    )

    assert_equal(
      {
        "amount" => "1000",
        "currency" => "USDC",
        "recipient" => "recipient",
        "description" => "API call",
        "externalId" => "order-001",
        "methodDetails" => {"network" => "localnet"}
      },
      request.to_h
    )
  end

  def test_from_hash_with_optional_fields_absent
    request = Mpp::Intent::ChargeRequest.from_h({"amount" => "1", "currency" => "SOL"})

    assert_equal "1", request.amount
    assert_equal "SOL", request.currency
    assert_nil request.recipient
    assert_empty request.method_details
  end

  def test_parse_units_boundaries
    assert_equal "1500000", Mpp::Intent::ChargeRequest.parse_units("1.5", 6)
    assert_equal "1", Mpp::Intent::ChargeRequest.parse_units("0.000001", 6)
    assert_equal "0", Mpp::Intent::ChargeRequest.parse_units("0", 6)
    assert_raises(ArgumentError) { Mpp::Intent::ChargeRequest.parse_units("0.0000001", 6) }
    assert_raises(ArgumentError) { Mpp::Intent::ChargeRequest.parse_units("abc", 6) }
  end

  def test_rejects_zero_and_invalid_method_details
    assert_raises(ArgumentError) { Mpp::Intent::ChargeRequest.new(amount: "0", currency: "SOL") }
    assert_raises(ArgumentError) { Mpp::Intent::ChargeRequest.new(amount: "1", currency: "") }
    assert_raises(ArgumentError) { Mpp::Intent::ChargeRequest.new(amount: "1", currency: "SOL", method_details: "bad") }
    assert_raises(ArgumentError) { Mpp::Intent::ChargeRequest.from_h("bad") }
  end
end
