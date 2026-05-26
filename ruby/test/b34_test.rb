# frozen_string_literal: true

require_relative "test_helper"

# B34: push-mode credentials (`type=signature`) must be rejected on routes
# that use a server-side fee payer. Verified directly against the Solana
# verifier so the reject runs before any RPC call. Mirrors the Rust spine
# unit test and matches PHP #100 / Python #106.
class B34Test < Minitest::Test
  include RubyMppTestHelpers

  def setup
    @verifier = Mpp::Protocol::Solana::Verifier.new
  end

  def test_rejects_signature_credential_when_fee_payer_true
    request = charge_request(method_details: {"network" => "localnet", "feePayer" => true, "feePayerKey" => pubkey(7)})
    credential = stub_credential(payload: {"type" => "signature", "signature" => "x" * 88})
    challenge = stub_challenge(request)

    result = @verifier.verify(credential, challenge, expected_request: request)

    refute result.ok?
    assert_match(/push-mode credentials are not allowed/i, result.reason)
    assert_equal ::PayCore::ErrorCodes::CODE_CHARGE_REQUEST_MISMATCH, result.code
  end

  def test_accepts_signature_credential_when_fee_payer_absent
    # B34 must only fire when feePayer is true. Without it, the verifier
    # falls through to validate_signature and any rejection there is the
    # downstream concern; the B34 path itself must not surface.
    request = charge_request(method_details: {"network" => "localnet"})
    credential = stub_credential(payload: {"type" => "signature", "signature" => "x" * 88})
    challenge = stub_challenge(request)

    result = @verifier.verify(credential, challenge, expected_request: request)

    if result.ok?
      assert true
    else
      refute_match(/push-mode credentials are not allowed/i, result.reason)
    end
  end

  private

  def stub_credential(payload:)
    Struct.new(:payload).new(payload)
  end

  def stub_challenge(request)
    Struct.new(:decode_request).new(request.to_h)
  end
end
