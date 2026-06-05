# frozen_string_literal: true

# CAIP-2 network-identifier helper tests for the Ruby SDK. Covers the
# `for_cluster` normalizer added for x402 EXACT v1, which maps the legacy
# plain SVM slugs ("solana", "solana-devnet", "solana-testnet") and the
# friendly cluster names to canonical CAIP-2 IDs. Mirrors the Rust spine
# `caip2_network_for_cluster`
# (rust/crates/x402/src/protocol/schemes/exact/types.rs:31-39).
require_relative "../test_helper"

class Caip2Test < Minitest::Test
  include RubyMppTestHelpers

  Caip2 = ::PayCore::Solana::Caip2

  def test_resolve_passes_through_caip2_and_maps_friendly_names
    assert_equal Caip2::DEVNET, Caip2.resolve("devnet")
    assert_equal Caip2::MAINNET, Caip2.resolve("mainnet")
    assert_equal Caip2::TESTNET, Caip2.resolve("testnet")
    assert_equal Caip2::DEVNET, Caip2.resolve(Caip2::DEVNET)
    # Unknown names pass through unchanged (legacy behaviour).
    assert_equal "solana-devnet", Caip2.resolve("solana-devnet")
  end

  def test_for_cluster_normalizes_legacy_v1_slugs
    assert_equal Caip2::MAINNET, Caip2.for_cluster("solana")
    assert_equal Caip2::DEVNET, Caip2.for_cluster("solana-devnet")
    assert_equal Caip2::TESTNET, Caip2.for_cluster("solana-testnet")
  end

  def test_for_cluster_normalizes_friendly_and_caip2_forms
    assert_equal Caip2::MAINNET, Caip2.for_cluster("mainnet")
    assert_equal Caip2::MAINNET, Caip2.for_cluster("mainnet-beta")
    assert_equal Caip2::DEVNET, Caip2.for_cluster("devnet")
    assert_equal Caip2::DEVNET, Caip2.for_cluster("localnet")
    assert_equal Caip2::TESTNET, Caip2.for_cluster("testnet")

    assert_equal Caip2::MAINNET, Caip2.for_cluster(Caip2::MAINNET)
    assert_equal Caip2::DEVNET, Caip2.for_cluster(Caip2::DEVNET)
    assert_equal Caip2::TESTNET, Caip2.for_cluster(Caip2::TESTNET)
  end

  def test_for_cluster_falls_back_to_mainnet_for_unknown
    # Matches the Rust spine catch-all arm (types.rs:38).
    assert_equal Caip2::MAINNET, Caip2.for_cluster("not-a-network")
    assert_equal Caip2::MAINNET, Caip2.for_cluster(nil)
  end
end
