# frozen_string_literal: true

require_relative "../test_helper"

class TransactionTest < Minitest::Test
  include RubyMppTestHelpers

  def test_parses_and_serializes_v0_transaction
    payer = pubkey(1)
    recipient = pubkey(2)
    raw = v0_transaction(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )

    tx = ::PayCore::Solana::Transaction.from_bytes(raw)

    assert_equal 0, tx.version
    assert_equal payer, tx.message.account_keys[0]
    assert_equal recipient, tx.message.account_keys[1]
    assert_equal raw, tx.to_bytes
    assert_match(/\A[1-9A-HJ-NP-Za-km-z]+\z/, tx.primary_signature)
  end

  def test_parses_and_serializes_legacy_transaction
    payer = pubkey(1)
    recipient = pubkey(2)
    raw = legacy_transaction(
      account_keys: [payer, recipient, PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    )

    tx = ::PayCore::Solana::Transaction.from_bytes(raw)

    assert_equal "legacy", tx.version
    assert_equal payer, tx.message.account_keys[0]
    assert_equal recipient, tx.message.account_keys[1]
    assert_empty tx.message.address_table_lookups
    assert_equal raw, tx.to_bytes
    assert_equal raw, ::PayCore::Solana::Transaction.from_base64(Base64.strict_encode64(raw)).to_bytes
  end

  def test_rejects_trailing_bytes_after_either_message_framing
    account_keys = [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM]
    instructions = [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    [
      v0_transaction(account_keys: account_keys, instructions: instructions),
      legacy_transaction(account_keys: account_keys, instructions: instructions)
    ].each do |raw|
      error = assert_raises(ArgumentError) { ::PayCore::Solana::Transaction.from_bytes(raw + "\x00".b) }
      assert_match(/trailing bytes after transaction message/, error.message)
    end
  end

  def test_parses_v0_transaction_without_address_lookups
    payer = pubkey(1)
    recipient = pubkey(2)
    message = +""
    message << [0x80, 1, 0, 0].pack("C*")
    message << compact_u16(3)
    [payer, recipient, PROGRAMS::SYSTEM_PROGRAM].each { |key| message << ::PayCore::Solana::Base58.decode(key) }
    message << ::PayCore::Solana::Base58.decode(pubkey(9))
    message << compact_u16(1)
    message << compiled_instruction(2, [0, 1], u32(2) + u64(1000))
    message << compact_u16(0)
    raw = compact_u16(1) + ("\x00".b * 64) + message

    tx = ::PayCore::Solana::Transaction.from_bytes(raw)

    assert_equal 0, tx.version
    assert_empty tx.message.address_table_lookups
    assert_equal raw, tx.to_bytes
  end

  def test_rejects_truncated_transaction
    assert_raises(ArgumentError) { ::PayCore::Solana::Transaction.from_bytes("\x01\x00".b) }
  end

  def test_rejects_unsupported_version_and_signer_not_found
    raw = compact_u16(0) + [0x81, 1, 0, 0].pack("C*")
    assert_raises(ArgumentError) { ::PayCore::Solana::Transaction.from_bytes(raw) }

    tx = ::PayCore::Solana::Transaction.from_bytes(v0_transaction(
      account_keys: [pubkey(1), pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))
    keypair = ::PayCore::Solana::Account.new(Array.new(64, 9))
    assert_raises(::PayCore::Solana::Transaction::SigningError) { tx.sign_with(keypair) }
  end

  def test_rejects_fee_payer_when_not_required_signer
    keypair = ::PayCore::Solana::Account.new(Array.new(64, 1))
    tx = ::PayCore::Solana::Transaction.from_bytes(v0_transaction(
      account_keys: [keypair.public_key.to_s, pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      signatures: [],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))

    assert_raises(::PayCore::Solana::Transaction::SigningError) { tx.sign_with(keypair) }
  end

  # Only the named server signer's slot may stay empty; every other slot
  # must verify, and the list must match the header's required signers.
  def test_signatures_verify_exempts_only_the_server_slot
    empty = "\x00".b * 64
    keys = [pubkey(1), signer_pubkey(6), pubkey(2), PROGRAMS::SYSTEM_PROGRAM]
    instructions = [compiled_instruction(3, [1, 2], u32(2) + u64(1000))]
    wire = v0_transaction(account_keys: keys, instructions: instructions, signatures: [empty, empty], signer: {1 => 6})
    transaction = ::PayCore::Solana::Transaction.from_bytes(wire)

    assert transaction.signature_slots_match?
    assert transaction.signatures_verify?(server_signer: pubkey(1))
    refute transaction.signatures_verify?
    refute transaction.signatures_verify?(server_signer: signer_pubkey(6))

    truncated = ::PayCore::Solana::Transaction.from_bytes(compact_u16(1) + wire.byteslice(65, wire.bytesize - 65))
    refute truncated.signature_slots_match?
    refute truncated.signatures_verify?(server_signer: pubkey(1))
  end

  def test_signs_when_fee_payer_is_required_signer
    keypair = ::PayCore::Solana::Account.new(Array.new(64, 1))
    tx = ::PayCore::Solana::Transaction.from_bytes(v0_transaction(
      account_keys: [keypair.public_key.to_s, pubkey(2), PROGRAMS::SYSTEM_PROGRAM],
      signatures: ["\x00".b * 64],
      instructions: [compiled_instruction(2, [0, 1], u32(2) + u64(1000))]
    ))

    tx.sign_with(keypair)

    refute_equal "\x00".b * 64, tx.signatures.first
  end

  def test_from_base64_invalid_and_cursor_boundaries
    assert_raises(ArgumentError) { ::PayCore::Solana::Transaction.from_base64("%%%") }
    assert_equal [0x80, 0x01].pack("C*"), ::PayCore::Solana::Transaction.compact_u16(128)
    assert_equal [128, 2], ::PayCore::Solana::Transaction.read_short_vec("\x80\x01".b, 0)
    assert_raises(ArgumentError) { ::PayCore::Solana::Transaction.read_short_vec("".b, 0) }
    cursor = ::PayCore::Solana::Cursor.new("\xff\xff\xff\xff".b)
    assert_raises(ArgumentError) { cursor.compact_u16 }
    assert_raises(ArgumentError) { ::PayCore::Solana::Cursor.new("").peek }
    assert_raises(ArgumentError) { ::PayCore::Solana::Cursor.new("").byte }
    assert_raises(ArgumentError) { ::PayCore::Solana::Cursor.new("a").bytes(2) }
  end

  def test_derives_associated_token_address
    owner = "11111111111111111111111111111111"
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"

    ata = ::PayCore::Solana::ATA.derive(
      owner: owner,
      mint: mint,
      token_program: PROGRAMS::TOKEN_PROGRAM
    )

    assert_match(/\A[1-9A-HJ-NP-Za-km-z]{32,44}\z/, ata)
  end

  def test_program_address_derivation_handles_high_bump_bytes
    program_id = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

    _address, bump = ::PayCore::Solana::PublicKey.find_program_address(["seed"], program_id)

    assert_operator bump, :<=, 255
    assert_equal 1, [bump].pack("C").bytesize
  end
end
