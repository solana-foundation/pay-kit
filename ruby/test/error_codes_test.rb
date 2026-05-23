# frozen_string_literal: true

require_relative "test_helper"

class ErrorCodesTest < Minitest::Test
  include Mpp::ErrorCodes

  def test_canonical_codes_are_exposed
    assert_equal "charge_request_mismatch", CODE_CHARGE_REQUEST_MISMATCH
    assert_equal "challenge_route_mismatch", CODE_CHALLENGE_ROUTE_MISMATCH
    assert_equal "challenge_verification_failed", CODE_CHALLENGE_VERIFICATION_FAILED
    assert_equal "challenge_expired", CODE_CHALLENGE_EXPIRED
    assert_equal "payment_invalid", CODE_PAYMENT_INVALID
    assert_equal "wrong_network", CODE_WRONG_NETWORK
    assert_equal "signature_consumed", CODE_SIGNATURE_CONSUMED
  end

  def test_canonical_code_passes_through_canonical_inputs
    CANONICAL_CODES.each do |code|
      assert_equal code, Mpp::ErrorCodes.canonical_code(code)
    end
  end

  def test_canonical_code_maps_legacy_kebab_to_canonical
    {
      "challenge-expired" => CODE_CHALLENGE_EXPIRED,
      "challenge-mismatch" => CODE_CHALLENGE_VERIFICATION_FAILED,
      "signature-consumed" => CODE_SIGNATURE_CONSUMED,
      "wrong-network" => CODE_WRONG_NETWORK,
      "amount-mismatch" => CODE_CHARGE_REQUEST_MISMATCH,
      "recipient-mismatch" => CODE_CHARGE_REQUEST_MISMATCH,
      "splits-exceed-amount" => CODE_CHARGE_REQUEST_MISMATCH,
      "invalid-payload" => CODE_PAYMENT_INVALID,
      "transaction-failed" => CODE_PAYMENT_INVALID,
      "transaction-not-found" => CODE_PAYMENT_INVALID,
      "no-transfer" => CODE_PAYMENT_INVALID
    }.each do |legacy, canonical|
      assert_equal canonical, Mpp::ErrorCodes.canonical_code(legacy)
    end
  end

  def test_canonical_code_classifies_signature_consumed_message
    assert_equal CODE_SIGNATURE_CONSUMED, Mpp::ErrorCodes.canonical_code("Transaction signature already consumed")
  end

  def test_canonical_code_classifies_challenge_messages
    assert_equal CODE_CHALLENGE_VERIFICATION_FAILED, Mpp::ErrorCodes.canonical_code("challenge verification failed")
    assert_equal CODE_CHALLENGE_EXPIRED, Mpp::ErrorCodes.canonical_code("challenge expired")
  end

  def test_canonical_code_classifies_wrong_network_message
    msg = "Signed against localnet but the server expects mainnet. Switch your client RPC to mainnet and re-sign."
    assert_equal CODE_WRONG_NETWORK, Mpp::ErrorCodes.canonical_code(msg)
  end

  def test_canonical_code_classifies_mismatch_messages
    assert_equal CODE_CHARGE_REQUEST_MISMATCH, Mpp::ErrorCodes.canonical_code("Amount mismatch: credential has 100 but endpoint expects 200")
    assert_equal CODE_CHARGE_REQUEST_MISMATCH, Mpp::ErrorCodes.canonical_code("Currency mismatch: credential has USDC but endpoint expects USDT")
    assert_equal CODE_CHARGE_REQUEST_MISMATCH, Mpp::ErrorCodes.canonical_code("Recipient mismatch")
    assert_equal CODE_CHARGE_REQUEST_MISMATCH, Mpp::ErrorCodes.canonical_code("Method details mismatch")
    assert_equal CODE_CHARGE_REQUEST_MISMATCH, Mpp::ErrorCodes.canonical_code("split amounts exceed total amount")
    assert_equal CODE_CHARGE_REQUEST_MISMATCH, Mpp::ErrorCodes.canonical_code("too many splits")
  end

  def test_canonical_code_classifies_route_mismatch_messages
    assert_equal CODE_CHALLENGE_ROUTE_MISMATCH, Mpp::ErrorCodes.canonical_code("Credential method does not match this server")
    assert_equal CODE_CHALLENGE_ROUTE_MISMATCH, Mpp::ErrorCodes.canonical_code("Credential intent is not a charge")
    assert_equal CODE_CHALLENGE_ROUTE_MISMATCH, Mpp::ErrorCodes.canonical_code("Credential realm does not match this server")
  end

  def test_canonical_code_falls_back_to_payment_invalid
    assert_equal CODE_PAYMENT_INVALID, Mpp::ErrorCodes.canonical_code("some unrecognised error")
    assert_equal CODE_PAYMENT_INVALID, Mpp::ErrorCodes.canonical_code(nil)
    assert_equal CODE_PAYMENT_INVALID, Mpp::ErrorCodes.canonical_code("")
  end

  def test_mpp_error_carries_code
    error = Mpp::Error.new("boom", code: CODE_SIGNATURE_CONSUMED)
    assert_equal "boom", error.message
    assert_equal CODE_SIGNATURE_CONSUMED, error.code
  end

  def test_mpp_error_defaults_code_to_nil
    error = Mpp::Error.new("boom")
    assert_nil error.code
  end

  def test_verification_error_inherits_code
    error = Mpp::VerificationError.new("nope", code: CODE_WRONG_NETWORK)
    assert_equal CODE_WRONG_NETWORK, error.code
    assert_kind_of Mpp::Error, error
  end

  def test_verification_result_failure_carries_code
    result = Mpp::Methods::Solana::VerificationResult.failure("Amount mismatch", code: CODE_CHARGE_REQUEST_MISMATCH)
    refute result.ok?
    assert_equal "Amount mismatch", result.reason
    assert_equal CODE_CHARGE_REQUEST_MISMATCH, result.code
  end

  def test_verification_result_failure_code_defaults_to_nil
    result = Mpp::Methods::Solana::VerificationResult.failure("oops")
    assert_nil result.code
  end
end
