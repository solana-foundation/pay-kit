# frozen_string_literal: true

require_relative "test_helper"

class PayKitKmsTest < Minitest::Test
  # The KMS namespace is a forward-compatibility reservation. Every
  # factory is expected to raise `PayKit::NotImplementedError` until
  # remote enclave signers ship. These tests pin the namespace shape so
  # later releases can flip the raise to a real implementation without
  # renaming the public API.

  def test_gcp_raises_not_implemented
    error = assert_raises(PayKit::NotImplementedError) do
      PayKit::Kms.gcp(key_name: "projects/x/locations/global/keyRings/y/cryptoKeys/z", pubkey: "pub")
    end
    assert_match(/Kms\.gcp/, error.message)
    assert_match(/PayKit::Signer/, error.message)
  end

  def test_aws_raises_not_implemented
    error = assert_raises(PayKit::NotImplementedError) do
      PayKit::Kms.aws(key_id: "arn:aws:kms:us-east-1:..:key/abc", region: "us-east-1", pubkey: "pub")
    end
    assert_match(/Kms\.aws/, error.message)
  end

  def test_vault_raises_not_implemented
    error = assert_raises(PayKit::NotImplementedError) do
      PayKit::Kms.vault(addr: "https://vault.example.com", path: "transit/keys/x", pubkey: "pub")
    end
    assert_match(/Kms\.vault/, error.message)
  end

  def test_not_implemented_error_is_a_pay_kit_error
    assert_operator PayKit::NotImplementedError, :<, PayKit::Error
  end

  def test_gcp_requires_both_kwargs
    assert_raises(ArgumentError) { PayKit::Kms.gcp(key_name: "x") }
    assert_raises(ArgumentError) { PayKit::Kms.gcp(pubkey: "y") }
  end

  def test_aws_requires_three_kwargs
    assert_raises(ArgumentError) { PayKit::Kms.aws(key_id: "k", region: "us-east-1") }
    assert_raises(ArgumentError) { PayKit::Kms.aws(key_id: "k", pubkey: "p") }
  end

  def test_vault_requires_three_kwargs
    assert_raises(ArgumentError) { PayKit::Kms.vault(addr: "https://v", path: "p") }
  end
end
