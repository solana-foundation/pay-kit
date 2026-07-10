# frozen_string_literal: true

require_relative "../../../test_helper"

class ExactVerifierManagedSignersTest < Minitest::Test
  Exact = PayKit::Protocols::X402::Protocol::Schemes::Exact
  Verifier = Exact::Verifier
  ASSET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
  RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
  TOKEN_PROGRAM = Exact.base58_decode(::PayCore::Solana::Mints::TOKEN_PROGRAM)
  MINT = Exact.base58_decode(ASSET)
  EXPECTED_DESTINATION = Exact.associated_token_address(
    Exact.base58_decode(RECIPIENT),
    TOKEN_PROGRAM,
    MINT
  )

  def test_rejects_a_managed_source
    managed = raw_key(1)

    error = assert_raises(RuntimeError) do
      verify_transfer(source: managed, managed_signers: [managed])
    end

    assert_equal fee_payer_transferring_funds, error.message
  end

  def test_rejects_a_managed_tail_signer_account
    managed = raw_key(2)

    error = assert_raises(RuntimeError) do
      verify_transfer(managed_signers: [managed], tail_accounts: [managed])
    end

    assert_equal fee_payer_transferring_funds, error.message
  end

  def test_rejects_a_managed_authority
    managed = raw_key(3)

    error = assert_raises(RuntimeError) do
      verify_transfer(authority: managed, managed_signers: [managed])
    end

    assert_equal fee_payer_transferring_funds, error.message
  end

  def test_rejects_the_derived_managed_source_ata
    managed = raw_key(4)
    source = Exact.associated_token_address(managed, TOKEN_PROGRAM, MINT)

    error = assert_raises(RuntimeError) do
      verify_transfer(source: source, managed_signers: [managed])
    end

    assert_equal fee_payer_transferring_funds, error.message
  end

  def test_allows_a_managed_signer_at_an_unrelated_transfer_reference
    transfer = verify_transfer(managed_signers: [MINT])

    assert_equal TOKEN_PROGRAM, transfer.fetch(:token_program)
  end

  private

  def verify_transfer(source: raw_key(5), authority: raw_key(6), tail_accounts: [], managed_signers: [])
    account_keys = [TOKEN_PROGRAM, source, MINT, EXPECTED_DESTINATION, authority] + tail_accounts
    instruction = {
      program_index: 0,
      accounts: [1, 2, 3, 4] + (5...(5 + tail_accounts.length)).to_a,
      data: [12].pack("C") + [1000].pack("Q<") + [6].pack("C")
    }
    requirement = {"asset" => ASSET, "payTo" => RECIPIENT, "amount" => "1000"}

    Verifier.verify_transfer_instruction!(instruction, account_keys, requirement, managed_signers)
  end

  def raw_key(byte)
    (byte.chr * 32).b
  end

  def fee_payer_transferring_funds
    "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"
  end
end
