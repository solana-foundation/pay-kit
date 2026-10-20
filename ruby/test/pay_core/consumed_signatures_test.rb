# frozen_string_literal: true

require_relative "../test_helper"
require "tmpdir"

class ConsumedSignaturesTest < Minitest::Test
  STORES = {
    "mpp memory" => -> { PayKit::Protocols::Mpp::MemoryStore.new },
    "mpp file" => -> { PayKit::Protocols::Mpp::FileStore.new(File.join(Dir.mktmpdir, "replay.json")) },
    "x402 settlement cache" => -> { PayKit::Protocols::X402::Server::Exact::SettlementCache.new }
  }.freeze

  # A signature claimed under a pre-ledger MPP or x402 key (by an older
  # replica, or just before an upgrade) stays consumed, and the legacy record
  # is only read, never rewritten.
  ["solana-charge:consumed:", "x402-svm-exact:consumed:"].each do |prefix|
    STORES.each do |name, build|
      define_method("test_pre_ledger_#{prefix.split(":").first.tr("-", "_")}_claim_stays_consumed_in_#{name.tr(" ", "_")}") do
        store = build.call
        store.put_if_absent("#{prefix}sig-legacy", true)
        ledger = PayCore::ConsumedSignatures.new(store)

        refute ledger.claim("sig-legacy")
        refute store.key?(PayCore::ConsumedSignatures.key("sig-legacy"))
        assert store.key?("#{prefix}sig-legacy")

        # Signatures without a legacy record claim normally, once.
        assert ledger.claim("sig-fresh")
        refute ledger.claim("sig-fresh")
      end
    end
  end

  def test_store_without_a_read_probe_is_refused_at_construction
    write_only = Class.new { def put_if_absent(_key, _value) = true }.new
    assert_raises(ArgumentError) { PayCore::ConsumedSignatures.new(write_only) }
  end
end
