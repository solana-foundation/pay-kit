# frozen_string_literal: true

if ENV["COVERAGE"] == "1"
  require "simplecov"
  SimpleCov.enable_coverage :branch
  SimpleCov.start do
    add_filter "/test/"
    add_filter "/examples/"
    # The x402 protocol layer (wire types, verifier, exact server) binds
    # live Solana RPC + a facilitator fee payer and is exercised through
    # the cross-language harness rather than isolated unit tests,
    # so the whole `protocols/x402/` tree stays out of the branch gate
    # (the same exclusion the pre-refactor layout applied to `lib/x402/`).
    add_filter "/lib/pay_kit/protocols/x402/"
    # The umbrella adapters + their per-protocol loaders bridge the gate
    # to each protocol over live Solana RPC + signing; they are exercised
    # through the Sinatra example (manual curl DX) plus the harness
    # harness. Unit-testing them in isolation would require mocking the
    # entire SVM client stack.
    add_filter "/lib/pay_kit/protocols/mpp.rb"
    add_filter "/lib/pay_kit/protocols/x402.rb"
    add_filter "/lib/pay_kit/protocols/mpp/runtime.rb"
    add_filter "/lib/pay_kit/protocols/mpp/sinatra.rb"
    # `lib/pay_kit/rack/` wraps the dispatch loop over the same live
    # adapters; same rationale.
    add_filter "/lib/pay_kit/rack/"
    # `lib/pay_kit/preflight.rb` issues live RPC calls (`getBalance`,
    # `getAccountInfo`) and Surfnet cheatcodes against the configured
    # endpoint at `PayKit.configure` time. Unit-testing it in isolation
    # would require mocking the entire RPC stack; the integration
    # behaviour is exercised through the Sinatra example. Follows the
    # same pattern as `/lib/pay_kit/rack/` + `/lib/pay_kit/protocols/`.
    add_filter "/lib/pay_kit/preflight.rb"
    # Cross-SDK baseline target is 90 percent branch coverage. Line
    # coverage stays at 92 since the suite already exceeds that.
    minimum_coverage line: 92, branch: 90
  end
end

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

# Preflight makes real RPC calls at PayKit.configure time. Tests run
# offline; the live preflight in PayKit.configure would either slow the
# suite to a crawl or fail when surfnet is unreachable.
ENV["PAY_KIT_DISABLE_PREFLIGHT"] = "1"

require "minitest/autorun"
require "pay_kit"

module RubyMppTestHelpers
  PROGRAMS = ::PayCore::Solana::Mints

  def base58(bytes)
    ::PayCore::Solana::Base58.encode(bytes.pack("C*"))
  end

  def pubkey(byte)
    base58([byte] * 32)
  end

  def compact_u16(value)
    ::PayCore::Solana::Transaction.compact_u16(value)
  end

  def u32(value)
    [value].pack("L<")
  end

  def u64(value)
    [value].pack("Q<")
  end

  def compiled_instruction(program_index, accounts, data)
    [program_index].pack("C") + compact_u16(accounts.length) + accounts.pack("C*") + compact_u16(data.bytesize) + data
  end

  def legacy_transaction(account_keys:, instructions:, recent_blockhash: pubkey(9), signatures: nil)
    keys = account_keys.map { |key| ::PayCore::Solana::Base58.decode(key) }
    message = +""
    message << [signatures&.length || 1, 0, 0].pack("C*")
    message << compact_u16(keys.length)
    keys.each { |key| message << key }
    message << ::PayCore::Solana::Base58.decode(recent_blockhash)
    message << compact_u16(instructions.length)
    instructions.each { |ix| message << ix }
    sigs = signatures || ["\x00".b * 64]
    compact_u16(sigs.length) + sigs.join + message
  end

  def charge_request(overrides = {})
    PayKit::Protocols::Mpp::Protocol::Intents::ChargeRequest.new(
      amount: "1000",
      currency: "SOL",
      recipient: pubkey(2),
      method_details: {"network" => "localnet", "decimals" => 6}, **overrides
    )
  end
end
