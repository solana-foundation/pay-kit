# frozen_string_literal: true

require_relative "../../../test_helper"

require "base64"
require "json"
require "open3"
require "rbconfig"
require_relative "../../../support/x402_exact_client_fixture"

class ConformanceX402ExactVerifierTest < Minitest::Test
  CONFORMANCE_RUNNER = File.expand_path("../../../../exe/conformance", __dir__)
  Exact = PayKit::Protocols::X402::Protocol::Schemes::Exact
  NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
  RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
  ASSET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
  BLOCKHASH = "11111111111111111111111111111111"

  def test_verify_x402_transaction_allows_a_managed_mint_reference
    result = run_vector(build_transaction, managed_signers: [ASSET])

    assert_equal "accept", result.fetch("outcome")
  end

  def test_verify_x402_transaction_preserves_the_exact_verifier_reject_code
    transaction = build_transaction
    expected = [12].pack("C") + [1000].pack("Q<") + [6].pack("C")
    offset = transaction.index(expected)
    refute_nil offset, "expected exact fixture to contain TransferChecked"
    transaction[offset, expected.bytesize] = [12].pack("C") + [999].pack("Q<") + [6].pack("C")

    result = run_vector(transaction)

    assert_equal "reject", result.fetch("outcome")
    assert_equal "invalid_exact_svm_payload_amount_mismatch", result.fetch("x402ExactRejectCode")
    assert_equal result.fetch("x402ExactRejectCode"), result.fetch("error")
  end

  private

  def run_vector(transaction, managed_signers: [fee_payer])
    vector = {
      "id" => "ruby-x402-exact-invalid-transaction",
      "intent" => "x402-exact",
      "mode" => "verify-x402-transaction",
      "input" => {
        "transaction" => Base64.strict_encode64(transaction),
        "x402ExactRequirement" => requirement,
        "x402ExactManagedSigners" => managed_signers
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

  def build_transaction
    X402ExactClientFixture.build_transaction(
      requirement: requirement,
      private_key: Exact.private_key_from_json(JSON.generate((1..64).to_a)),
      recent_blockhash: BLOCKHASH
    )
  end

  def requirement
    @requirement ||= {
      "scheme" => "exact",
      "network" => NETWORK,
      "amount" => "1000",
      "asset" => ASSET,
      "payTo" => RECIPIENT,
      "extra" => {
        "feePayer" => fee_payer,
        "decimals" => 6,
        "tokenProgram" => ::PayCore::Solana::Mints::TOKEN_PROGRAM
      }
    }
  end

  def fee_payer
    key = Exact.private_key_from_json(JSON.generate((65...129).map { |value| value % 256 }))
    Exact.base58_encode(key.raw_public_key)
  end
end
