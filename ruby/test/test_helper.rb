# frozen_string_literal: true

if ENV["COVERAGE"] == "1"
  require "simplecov"
  SimpleCov.enable_coverage :branch
  SimpleCov.start do
    add_filter "/test/"
    add_filter "/examples/"
    # Cross-SDK baseline target is 90 percent branch coverage. Line
    # coverage stays at 92 since the suite already exceeds that.
    minimum_coverage line: 92, branch: 90
  end
end

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "mpp"

module RubyMppTestHelpers
  PROGRAMS = Mpp::Methods::Solana::Mints

  def base58(bytes)
    Mpp::Methods::Solana::Base58.encode(bytes.pack("C*"))
  end

  def pubkey(byte)
    base58([byte] * 32)
  end

  def compact_u16(value)
    Mpp::Methods::Solana::Transaction.compact_u16(value)
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
    keys = account_keys.map { |key| Mpp::Methods::Solana::Base58.decode(key) }
    message = +""
    message << [signatures&.length || 1, 0, 0].pack("C*")
    message << compact_u16(keys.length)
    keys.each { |key| message << key }
    message << Mpp::Methods::Solana::Base58.decode(recent_blockhash)
    message << compact_u16(instructions.length)
    instructions.each { |ix| message << ix }
    sigs = signatures || ["\x00".b * 64]
    compact_u16(sigs.length) + sigs.join + message
  end

  def charge_request(overrides = {})
    Mpp::Intent::ChargeRequest.new(
      amount: "1000",
      currency: "SOL",
      recipient: pubkey(2),
      method_details: {"network" => "localnet", "decimals" => 6}, **overrides
    )
  end
end
