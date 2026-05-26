# frozen_string_literal: true

require_relative "test_helper"
require "pay_core"

# Regression suite for the `solana-pay-core` extraction. Confirms that:
#  - the shared Solana primitives live under `PayCore::Solana::*`
#  - the `Mpp::Methods::Solana::*` and `Mpp::Core::*` constants are
#    backward-compat aliases that resolve to the PayCore implementations
#  - canonical L6 error codes and CAIP-2 IDs have a single source of truth
class PayCoreTest < Minitest::Test
  def test_paycore_solana_base58_is_canonical_home
    decoded = PayCore::Solana::Base58.decode("11111111111111111111111111111111")
    assert_equal 32, decoded.bytesize
    re_encoded = PayCore::Solana::Base58.encode(decoded)
    assert_equal "11111111111111111111111111111111", re_encoded
  end

  def test_mpp_base58_alias_resolves_to_paycore
    assert_same PayCore::Solana::Base58, Mpp::Methods::Solana::Base58
  end

  def test_paycore_programs_owns_canonical_program_ids
    assert_equal "11111111111111111111111111111111", PayCore::Solana::Programs::SYSTEM_PROGRAM
    assert_equal "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", PayCore::Solana::Programs::TOKEN_PROGRAM
    assert_equal "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", PayCore::Solana::Programs::TOKEN_2022_PROGRAM
    assert_equal "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", PayCore::Solana::Programs::ASSOCIATED_TOKEN_PROGRAM
    assert_equal "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", PayCore::Solana::Programs::MEMO_PROGRAM
    assert_equal "ComputeBudget111111111111111111111111111111", PayCore::Solana::Programs::COMPUTE_BUDGET_PROGRAM
    assert_equal "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95", PayCore::Solana::Programs::LIGHTHOUSE_PROGRAM
  end

  def test_mints_program_id_constants_match_programs_constants
    # `PayCore::Solana::Mints` re-exports the canonical program IDs from
    # `PayCore::Solana::Programs`. Both sources MUST resolve to the same
    # string so layers that imported the constant from either location
    # behave identically.
    assert_equal PayCore::Solana::Programs::TOKEN_PROGRAM, PayCore::Solana::Mints::TOKEN_PROGRAM
    assert_equal PayCore::Solana::Programs::ASSOCIATED_TOKEN_PROGRAM, PayCore::Solana::Mints::ASSOCIATED_TOKEN_PROGRAM
    assert_equal PayCore::Solana::Programs::MEMO_PROGRAM, PayCore::Solana::Mints::MEMO_PROGRAM
  end

  def test_caip2_has_canonical_devnet_id
    assert_equal "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", PayCore::Solana::Caip2::DEVNET
    assert_equal "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", PayCore::Solana::Caip2::MAINNET
    assert_equal PayCore::Solana::Caip2::DEVNET, PayCore::Solana::Caip2.resolve("devnet")
    assert_equal PayCore::Solana::Caip2::MAINNET, PayCore::Solana::Caip2.resolve("mainnet")
    assert_equal PayCore::Solana::Caip2::DEVNET, PayCore::Solana::Caip2.resolve(PayCore::Solana::Caip2::DEVNET)
  end

  def test_x402_server_consumes_paycore_caip2_directly
    # The x402 server's default network MUST come from
    # `PayCore::Solana::Caip2`, not a redeclared literal.
    require "x402/server"
    assert_equal PayCore::Solana::Caip2::DEVNET, X402::Interop::Server::DEFAULT_NETWORK
  end

  def test_x402_client_caip2_constant_resolves_to_paycore
    require "x402/client"
    assert_equal PayCore::Solana::Caip2::DEVNET, X402::Interop::Client::SOLANA_DEVNET_CAIP2
  end

  def test_mpp_error_codes_alias_resolves_to_paycore
    assert_same PayCore::ErrorCodes, Mpp::ErrorCodes
    assert_equal "payment_invalid", PayCore::ErrorCodes::CODE_PAYMENT_INVALID
    assert_equal "signature_consumed", PayCore::ErrorCodes.canonical_code("already consumed")
  end

  def test_mpp_json_alias_resolves_to_paycore
    assert_same PayCore::Json, Mpp::Core::Json
    assert_equal "{\"a\":1,\"b\":2}", PayCore::Json.canonical_generate({"b" => 2, "a" => 1})
  end

  def test_mpp_rfc3339_parser_alias_resolves_to_paycore
    assert_same PayCore::Rfc3339Parser, Mpp::Core::Rfc3339Parser
  end

  def test_mpp_base64_url_alias_resolves_to_paycore
    assert_same PayCore::Base64Url, Mpp::Core::Base64Url
  end

  def test_paycore_solana_ata_is_canonical_home_for_derivation
    # Mpp::Methods::Solana::AssociatedToken is an alias to PayCore::Solana::ATA.
    assert_same PayCore::Solana::ATA, Mpp::Methods::Solana::AssociatedToken
  end

  def test_mpp_solana_rpc_subclasses_paycore_rpc
    assert_operator Mpp::Methods::Solana::Rpc, :<, PayCore::Solana::Rpc
  end

  def test_mpp_solana_transaction_subclasses_paycore_transaction
    assert_operator Mpp::Methods::Solana::Transaction, :<, PayCore::Solana::Transaction
  end

  def test_x402_exact_uses_paycore_for_short_vec
    # Confirm the shared compact-u16 encoder is reachable through PayCore
    # so x402 byte builders do not redeclare it.
    encoded = PayCore::Solana::Transaction.short_vec(0)
    assert_equal "\x00".b, encoded
    value, offset = PayCore::Solana::Transaction.read_short_vec("\x80\x01".b, 0)
    assert_equal 128, value
    assert_equal 2, offset
  end
end
