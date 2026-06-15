# frozen_string_literal: true

require_relative "../../../test_helper"

class ChargeRequestTest < Minitest::Test
  def test_serializes_camel_case_wire_fields
    request = PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(
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
    request = PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.from_h({"amount" => "1", "currency" => "SOL"})

    assert_equal "1", request.amount
    assert_equal "SOL", request.currency
    assert_nil request.recipient
    assert_empty request.method_details
  end

  def test_parse_units_boundaries
    assert_equal "1500000", PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.parse_units("1.5", 6)
    assert_equal "1", PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.parse_units("0.000001", 6)
    assert_equal "0", PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.parse_units("0", 6)
    assert_raises(ArgumentError) { PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.parse_units("0.0000001", 6) }
    assert_raises(ArgumentError) { PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.parse_units("abc", 6) }
  end

  def test_rejects_zero_and_invalid_method_details
    assert_raises(ArgumentError) { PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(amount: "0", currency: "SOL") }
    assert_raises(ArgumentError) { PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(amount: "1", currency: "") }
    assert_raises(ArgumentError) { PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(amount: "1", currency: "SOL", method_details: "bad") }
    assert_raises(ArgumentError) { PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.from_h("bad") }
  end

  # Rust spine parity (rust/crates/mpp/src/protocol/intents/charge.rs:53-58):
  # charge amounts are base-unit u64. An amount above u64::MAX must surface
  # as an explicit invalid-amount error from amount_i rather than passing
  # through to the on-chain transfer matcher as a "No matching transfer".
  # u64::MAX itself must parse.
  def test_amount_i_rejects_values_above_u64_max
    max = PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(amount: ((2**64) - 1).to_s, currency: "USDC")
    assert_equal (2**64) - 1, max.amount_i

    overflow = PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(amount: (2**64).to_s, currency: "USDC")
    error = assert_raises(ArgumentError) { overflow.amount_i }
    assert_match(/invalid amount/, error.message)
  end
end
