# frozen_string_literal: true

if ENV["COVERAGE"] == "1"
  require "simplecov"
  SimpleCov.enable_coverage :branch
  SimpleCov.start do
    add_filter "/test/"
    add_filter "/examples/"
    minimum_coverage line: 92, branch: 90
  end
end

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "minitest/autorun"
require "solana_mpp"

module RubyMppTestHelpers
  PROGRAMS = SolanaMpp::Common::StablecoinMints

  def base58(bytes)
    SolanaMpp::Solana::Base58.encode(bytes.pack("C*"))
  end

  def pubkey(byte)
    base58([byte] * 32)
  end

  def compact_u16(value)
    SolanaMpp::Solana::Transaction.compact_u16(value)
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
    keys = account_keys.map { |key| SolanaMpp::Solana::Base58.decode(key) }
    message = +""
    message << [signatures&.length || 1, 0, 0].pack("C*")
    message << compact_u16(keys.length)
    keys.each { |key| message << key }
    message << SolanaMpp::Solana::Base58.decode(recent_blockhash)
    message << compact_u16(instructions.length)
    instructions.each { |ix| message << ix }
    sigs = signatures || ["\x00".b * 64]
    compact_u16(sigs.length) + sigs.join + message
  end

  def charge_request(overrides = {})
    SolanaMpp::Intent::ChargeRequest.new(
      amount: "1000",
      currency: "SOL",
      recipient: pubkey(2),
      method_details: {"network" => "localnet", "decimals" => 6}, **overrides
    )
  end
end
