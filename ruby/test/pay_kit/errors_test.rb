# frozen_string_literal: true

require_relative "test_helper"

# Covers the umbrella error value objects (PayKit::Errors) and the
# PayKit::Challenge / PayKit::Payment envelopes they carry.
class PayKitErrorsTest < Minitest::Test
  def test_challenge_to_h_shape
    challenge = PayKit::Challenge.new(resource: "/x", accepts: [{a: 1}], headers: {})
    body = challenge.to_h
    assert_equal "payment_required", body[:error]
    assert_equal "/x", body[:resource]
    assert_equal [{a: 1}], body[:accepts]
  end

  def test_payment_protocol_predicates
    payment = PayKit::Payment.new(protocol: :x402, scheme: :exact,
      transaction: "sig", settlement_headers: {}, raw: "raw")
    assert payment.x402?
    refute payment.mpp?
  end

  def test_payment_required_carries_challenge
    challenge = PayKit::Challenge.new(resource: "/x", accepts: [], headers: {})
    error = PayKit::PaymentRequired.new(challenge)
    assert_equal challenge, error.challenge
    assert_match(/payment required/, error.message)
  end

  def test_invalid_proof_carries_code_and_detail
    error = PayKit::InvalidProof.new(:payment_invalid, "bad sig")
    assert_equal :payment_invalid, error.code
    assert_equal "bad sig", error.detail
    assert_equal "bad sig", error.message
  end

  def test_unknown_gate_message_includes_name
    error = PayKit::UnknownGate.new(:typo)
    assert_match(/typo/, error.message)
  end
end
