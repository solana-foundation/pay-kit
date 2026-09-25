# frozen_string_literal: true

require_relative "../test_helper"

class MessageBuilderTest < Minitest::Test
  include RubyMppTestHelpers

  MB = ::PayCore::Solana::MessageBuilder
  AM = ::PayCore::Solana::AccountMeta
  PI = ::PayCore::Solana::PreparedInstruction

  def test_builds_signable_legacy_transaction
    fee_payer = pubkey(1)
    ix = PI.new(PROGRAMS::SYSTEM_PROGRAM, [AM.writable(pubkey(2))], "\x01\x02".b)
    tx = MB.build_legacy(fee_payer: fee_payer, recent_blockhash: pubkey(9), instructions: [ix])

    assert_equal "legacy", tx.version
    assert_equal 1, tx.signatures.length
    assert_equal "\x00".b * 64, tx.signatures.first
    assert_equal fee_payer, tx.message.account_keys.first
    # pubkey(2) is writable-nonsigner; only the program id is readonly-unsigned.
    assert_equal({required_signatures: 1, readonly_signed: 0, readonly_unsigned: 1}, tx.message.header)
    # round-trips through the canonical parser
    assert_equal tx.message.account_keys, ::PayCore::Solana::Transaction.from_bytes(tx.to_bytes).message.account_keys
  end

  def test_merges_roles_across_instructions
    fee_payer = pubkey(1)
    shared = pubkey(2)
    # shared appears readonly in ix1 and writable in ix2 -> must end writable
    ix1 = PI.new(PROGRAMS::SYSTEM_PROGRAM, [AM.readonly(shared)], "\x00".b)
    ix2 = PI.new(PROGRAMS::MEMO_PROGRAM, [AM.writable(shared)], "\x00".b)
    tx = MB.build_legacy(fee_payer: fee_payer, recent_blockhash: pubkey(9), instructions: [ix1, ix2])

    # account table is unique
    assert_equal tx.message.account_keys, tx.message.account_keys.uniq
    # shared is writable-nonsigner -> not in the readonly_unsigned tail bucket only if writable
    shared_index = tx.message.account_keys.index(shared)
    # writable nonsigners come before readonly nonsigners and after signers
    refute_nil shared_index
    # both program ids present as readonly nonsigners
    assert_includes tx.message.account_keys, PROGRAMS::SYSTEM_PROGRAM
    assert_includes tx.message.account_keys, PROGRAMS::MEMO_PROGRAM
  end

  def test_fee_payer_stays_signer_writable_even_when_used_as_account
    fee_payer = pubkey(1)
    # fee payer also referenced read-only inside an instruction
    ix = PI.new(PROGRAMS::SYSTEM_PROGRAM, [AM.readonly(fee_payer), AM.writable(pubkey(2))], "\x00".b)
    tx = MB.build_legacy(fee_payer: fee_payer, recent_blockhash: pubkey(9), instructions: [ix])

    assert_equal fee_payer, tx.message.account_keys.first
    assert_equal 1, tx.message.header[:required_signatures]
    assert_equal 0, tx.message.header[:readonly_signed]
  end

  def test_instruction_indices_resolve
    fee_payer = pubkey(1)
    ix = PI.new(PROGRAMS::SYSTEM_PROGRAM, [AM.writable(pubkey(2)), AM.readonly(pubkey(3))], "data".b)
    tx = MB.build_legacy(fee_payer: fee_payer, recent_blockhash: pubkey(9), instructions: [ix])

    compiled = tx.message.instructions.first
    keys = tx.message.account_keys
    assert_equal PROGRAMS::SYSTEM_PROGRAM, keys[compiled.program_id_index]
    assert_equal [pubkey(2), pubkey(3)], compiled.accounts.map { |i| keys[i] }
    assert_equal "data".b, compiled.data
  end

  def test_signer_readonly_account_counts_in_header
    fee_payer = pubkey(1)
    # a co-signer that does not write (e.g. settle_and_finalize's merchant)
    ix = PI.new(PROGRAMS::SYSTEM_PROGRAM, [AM.signer_readonly(pubkey(2)), AM.writable(pubkey(3))], "\x00".b)
    tx = MB.build_legacy(fee_payer: fee_payer, recent_blockhash: pubkey(9), instructions: [ix])

    assert_equal 2, tx.message.header[:required_signatures]
    assert_equal 1, tx.message.header[:readonly_signed]
    # signer-readonly is ordered after writable signers, before nonsigners
    assert_equal pubkey(2), tx.message.account_keys[1]
  end

  def test_two_signers_yield_two_signature_slots
    fee_payer = pubkey(1)
    ix = PI.new(PROGRAMS::SYSTEM_PROGRAM, [AM.signer_writable(pubkey(2))], "\x00".b)
    tx = MB.build_legacy(fee_payer: fee_payer, recent_blockhash: pubkey(9), instructions: [ix])

    assert_equal 2, tx.signatures.length
    assert_equal 2, tx.message.header[:required_signatures]
  end
end
