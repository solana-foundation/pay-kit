# frozen_string_literal: true

if ENV["COVERAGE"] == "1"
  require "simplecov"
  SimpleCov.enable_coverage :branch
  SimpleCov.start do
    add_filter "/test/"
    add_filter "/examples/"
    # x402 production server helpers (`lib/x402/server/exact.rb` RPC
    # methods + bin) are exercised through the cross-language interop
    # harness rather than unit tests, so they remain excluded from
    # the branch-coverage gate. Library types + verifier
    # (`lib/x402/protocol/`, `lib/x402/constants.rb`, `lib/x402/error.rb`)
    # are covered by `test/x402_server_exact_test.rb`.
    add_filter "/lib/x402/"
    # `lib/pay_kit/rack/` and `lib/pay_kit/protocols/` wrap live Solana
    # RPC + signing through `X402::Server::Exact` and `Mpp::Server` and
    # are exercised through the Sinatra example (manual curl DX) plus
    # the cross-language interop harness; unit-testing them in isolation
    # would require mocking out the entire SVM client stack, so they
    # follow the same exclusion as `lib/x402/server/exact.rb`.
    add_filter "/lib/pay_kit/rack/"
    add_filter "/lib/pay_kit/protocols/"
    # Cross-SDK baseline target is 90 percent branch coverage. Line
    # coverage stays at 92 since the suite already exceeds that.
    minimum_coverage line: 92, branch: 90
  end
end

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "mpp"

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
    Mpp::Protocol::Intents::ChargeRequest.new(
      amount: "1000",
      currency: "SOL",
      recipient: pubkey(2),
      method_details: {"network" => "localnet", "decimals" => 6}, **overrides
    )
  end
end
