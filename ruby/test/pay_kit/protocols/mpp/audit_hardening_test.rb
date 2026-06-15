# frozen_string_literal: true

require_relative "../../../test_helper"

# Coverage for the server-side audit hardening:
#   #24 weak/short HMAC secret rejected at boot
#   #15 default realm derived per-recipient; empty realm rejected
#   #37 network allowlist at boot ({mainnet, devnet, localnet})
#   #21 split validation at issuance (count/parse/positive/overflow/dups)
#   #38 primary recipient in splits + ataCreationRequired rejected at issuance
class AuditHardeningTest < Minitest::Test
  include RubyMppTestHelpers

  STRONG_SECRET = "a-32-byte-or-longer-hmac-secret-000000"
  RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

  # Stub RPC so the SPL/arbitrary-mint resolution path never hits the network.
  class StubRpc
    def initialize(owner: nil, raise_on_owner: false)
      @owner = owner
      @raise_on_owner = raise_on_owner
    end

    def latest_blockhash = "TestBlockhashAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    def account_owner(_pubkey)
      raise "rpc unreachable" if @raise_on_owner

      @owner
    end
  end

  def method_fixture(network: "localnet", currency: "USDC")
    PayKit::Protocols::Mpp::Protocol::Solana.charge(
      recipient: RECIPIENT, currency: currency, network: network, rpc: StubRpc.new
    )
  end

  def server(secret: STRONG_SECRET, realm: PayKit::Protocols::Mpp::DEFAULT_REALM, **method_opts)
    PayKit::Protocols::Mpp.create(
      method: method_fixture(**method_opts),
      secret_key: secret,
      realm: realm,
      replay_store: PayKit::Protocols::Mpp::MemoryStore.new
    )
  end

  # --- #24 secret key gate ---------------------------------------------

  def test_rejects_empty_secret_key
    error = assert_raises(PayKit::Protocols::Mpp::Error) { server(secret: "") }
    assert_match(/at least 32 bytes/, error.message)
  end

  def test_rejects_short_secret_key
    error = assert_raises(PayKit::Protocols::Mpp::Error) { server(secret: "too-short") }
    assert_match(/at least 32 bytes/, error.message)
  end

  def test_accepts_secret_key_at_minimum_length
    assert_instance_of PayKit::Protocols::Mpp::Server::Charge, server(secret: "x" * 32)
  end

  # --- #15 realm derivation --------------------------------------------

  def test_default_realm_is_derived_per_recipient
    assert_match(/\AApp Id - #\d+\z/, server.realm)
  end

  def test_default_realm_is_deterministic_for_same_recipient
    assert_equal server.realm, server.realm
  end

  def test_default_realm_differs_across_recipients
    other = PayKit::Protocols::Mpp.create(
      method: PayKit::Protocols::Mpp::Protocol::Solana.charge(
        recipient: pubkey(9), currency: "USDC", network: "localnet", rpc: StubRpc.new
      ),
      secret_key: STRONG_SECRET,
      replay_store: PayKit::Protocols::Mpp::MemoryStore.new
    )
    refute_equal server.realm, other.realm
  end

  def test_rejects_empty_explicit_realm
    error = assert_raises(PayKit::Protocols::Mpp::Error) { server(realm: "") }
    assert_match(/realm must not be empty/, error.message)
  end

  def test_honours_explicit_non_empty_realm
    assert_equal "Acme API", server(realm: "Acme API").realm
  end

  # --- #37 network allowlist -------------------------------------------

  def test_accepts_canonical_networks
    %w[mainnet devnet localnet].each do |net|
      assert_instance_of(
        PayKit::Protocols::Mpp::Protocol::Solana::ChargeMethod,
        PayKit::Protocols::Mpp::Protocol::Solana.charge(recipient: RECIPIENT, currency: "USDC", network: net, rpc: StubRpc.new)
      )
    end
  end

  def test_rejects_mainnet_beta_slug
    error = assert_raises(PayKit::Protocols::Mpp::Error) do
      PayKit::Protocols::Mpp::Protocol::Solana.charge(recipient: RECIPIENT, currency: "USDC", network: "mainnet-beta", rpc: StubRpc.new)
    end
    assert_match(/Unsupported network/, error.message)
  end

  def test_rejects_unknown_network
    assert_raises(PayKit::Protocols::Mpp::Error) do
      PayKit::Protocols::Mpp::Protocol::Solana.charge(recipient: RECIPIENT, currency: "USDC", network: "testnet", rpc: StubRpc.new)
    end
  end

  # --- #28 arbitrary-mint token program resolution ---------------------

  def arbitrary_mint_method(rpc)
    PayKit::Protocols::Mpp::Protocol::Solana.charge(
      recipient: RECIPIENT, currency: pubkey(7), network: "localnet", rpc: rpc
    )
  end

  def test_arbitrary_mint_resolves_token_2022_owner_on_chain
    method = arbitrary_mint_method(StubRpc.new(owner: PayCore::Solana::Mints::TOKEN_2022_PROGRAM))
    assert_equal PayCore::Solana::Mints::TOKEN_2022_PROGRAM, method.token_program
    assert_equal PayCore::Solana::Mints::TOKEN_2022_PROGRAM, method.method_details["tokenProgram"]
  end

  def test_arbitrary_mint_resolves_legacy_token_owner_on_chain
    method = arbitrary_mint_method(StubRpc.new(owner: PayCore::Solana::Mints::TOKEN_PROGRAM))
    assert_equal PayCore::Solana::Mints::TOKEN_PROGRAM, method.token_program
  end

  def test_arbitrary_mint_rejects_non_token_owner
    method = arbitrary_mint_method(StubRpc.new(owner: PayCore::Solana::Mints::SYSTEM_PROGRAM))
    error = assert_raises(PayKit::Protocols::Mpp::Error) { method.token_program }
    assert_match(/not the SPL Token or Token-2022 program/, error.message)
  end

  def test_arbitrary_mint_rejects_when_rpc_unreachable
    method = arbitrary_mint_method(StubRpc.new(raise_on_owner: true))
    error = assert_raises(PayKit::Protocols::Mpp::Error) { method.token_program }
    assert_match(/Could not resolve the token program/, error.message)
  end

  def test_known_stablecoin_does_not_fetch_owner_on_chain
    # PYUSD is a known Token-2022 stablecoin; resolution comes from the static
    # table with no RPC round-trip (raise_on_owner would fire otherwise).
    method = PayKit::Protocols::Mpp::Protocol::Solana.charge(
      recipient: RECIPIENT, currency: "PYUSD", network: "mainnet", rpc: StubRpc.new(raise_on_owner: true)
    )
    assert_equal PayCore::Solana::Mints::TOKEN_2022_PROGRAM, method.token_program
  end

  # --- #21 split validation at issuance --------------------------------

  def charge_splits(splits)
    server.charge(nil, amount: "1000", splits: splits)
  end

  def test_accepts_valid_splits
    result = charge_splits([{"recipient" => pubkey(3), "amount" => "100"}])
    assert_instance_of PayKit::Protocols::Mpp::Challenge, result
  end

  def test_rejects_more_than_max_splits
    splits = 9.times.map { |i| {"recipient" => pubkey(i + 10), "amount" => "1"} }
    error = assert_raises(PayKit::Protocols::Mpp::VerificationError) { charge_splits(splits) }
    assert_match(/more than 8/, error.message)
  end

  def test_rejects_unparseable_split_recipient
    error = assert_raises(PayKit::Protocols::Mpp::VerificationError) { charge_splits([{"recipient" => "not-a-key!", "amount" => "1"}]) }
    assert_match(/not a valid base58 pubkey/, error.message)
  end

  def test_rejects_non_integer_split_amount
    error = assert_raises(PayKit::Protocols::Mpp::VerificationError) { charge_splits([{"recipient" => pubkey(3), "amount" => "1.5"}]) }
    assert_match(/integer string/, error.message)
  end

  def test_rejects_zero_split_amount
    error = assert_raises(PayKit::Protocols::Mpp::VerificationError) { charge_splits([{"recipient" => pubkey(3), "amount" => "0"}]) }
    assert_match(/greater than zero/, error.message)
  end

  def test_rejects_overflowing_split_amount
    error = assert_raises(PayKit::Protocols::Mpp::VerificationError) { charge_splits([{"recipient" => pubkey(3), "amount" => (2**64).to_s}]) }
    assert_match(/exceeds the maximum u64/, error.message)
  end

  def test_rejects_duplicate_split_recipients
    splits = [{"recipient" => pubkey(3), "amount" => "1"}, {"recipient" => pubkey(3), "amount" => "2"}]
    error = assert_raises(PayKit::Protocols::Mpp::VerificationError) { charge_splits(splits) }
    assert_match(/duplicate split recipient/, error.message)
  end

  # --- #38 primary-in-splits + ataCreationRequired ---------------------

  def test_rejects_primary_recipient_in_splits_with_ata_creation_required
    splits = [{"recipient" => RECIPIENT, "amount" => "100", "ataCreationRequired" => true}]
    error = assert_raises(PayKit::Protocols::Mpp::VerificationError) { charge_splits(splits) }
    assert_match(/primary recipient must not appear in splits with ataCreationRequired/, error.message)
  end

  def test_allows_primary_recipient_in_splits_without_ata_creation
    result = charge_splits([{"recipient" => RECIPIENT, "amount" => "100"}])
    assert_instance_of PayKit::Protocols::Mpp::Challenge, result
  end
end
