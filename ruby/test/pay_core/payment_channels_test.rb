# frozen_string_literal: true

require_relative "../test_helper"

# Byte-level parity tests for the hand-written payment-channels client. The
# golden vectors are lifted from the Go/Rust references so a Ruby encoder drift
# fails here, offline, before it ever reaches a validator.
class PaymentChannelsTest < Minitest::Test
  include RubyMppTestHelpers

  PC = ::PayCore::Solana::PaymentChannels
  ZERO_PUBKEY = "11111111111111111111111111111111" # 32 zero bytes

  # ---- voucher preimage --------------------------------------------------
  def test_voucher_message_bytes_matches_go_golden
    # go/protocols/programs/paymentchannels_parity_test/parity_test.go:123
    voucher = PC.voucher_message_bytes(ZERO_PUBKEY, 1_234_567, 4_102_444_800)
    expected = "000000000000000000000000000000000000000000000000000000000000000087d6120000000000005786f400000000"

    assert_equal 48, voucher.bytesize
    assert_equal expected, voucher.unpack1("H*")
  end

  def test_voucher_message_layout
    channel = pubkey(7)
    voucher = PC.voucher_message_bytes(channel, 500, 4_102_444_800)

    assert_equal ::PayCore::Solana::Base58.decode(channel), voucher.byteslice(0, 32)
    assert_equal 500, voucher.byteslice(32, 8).unpack1("Q<")
    assert_equal 4_102_444_800, voucher.byteslice(40, 8).unpack1("q<")
  end

  # ---- distribution hash -------------------------------------------------
  def test_empty_distribution_hash_matches_go_constant
    assert_equal 32, PC::EMPTY_DISTRIBUTION_HASH.bytesize
    assert_equal PC::EMPTY_DISTRIBUTION_HASH, PC.distribution_hash([])
    assert_equal Digest::SHA256.digest(u32(0)), PC.distribution_hash([])
    assert_equal "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119",
      PC::EMPTY_DISTRIBUTION_HASH.unpack1("H*")
  end

  def test_distribution_hash_preimage_layout
    recipients = [{recipient: pubkey(1), bps: 7_500}, {recipient: pubkey(2), bps: 2_500}]
    preimage = u32(2) +
      ::PayCore::Solana::Base58.decode(pubkey(1)) + [7_500].pack("v") +
      ::PayCore::Solana::Base58.decode(pubkey(2)) + [2_500].pack("v")

    assert_equal Digest::SHA256.digest(preimage), PC.distribution_hash(recipients)
  end

  # ---- settle_and_finalize ----------------------------------------------
  def test_settle_and_finalize_voucherless
    ixs = PC.settle_and_finalize_instructions(
      merchant: pubkey(5), channel: pubkey(6), authorized_signer: pubkey(5),
      signature: nil, cumulative: 0, expires_at: 100
    )

    assert_equal 1, ixs.length
    settle = ixs.first
    assert_equal PC::PROGRAM_ID, settle.program_id
    assert_equal "0400", settle.data.unpack1("H*")
    assert_equal [[true, false], [false, true], [false, false]],
      settle.accounts.map { |a| [a.signer, a.writable] }
    assert_equal [pubkey(5), pubkey(6), PC::INSTRUCTIONS_SYSVAR], settle.accounts.map(&:pubkey)
  end

  def test_settle_and_finalize_with_voucher
    signature = "\xAB".b * 64
    ixs = PC.settle_and_finalize_instructions(
      merchant: pubkey(5), channel: ZERO_PUBKEY, authorized_signer: pubkey(4),
      signature: signature, cumulative: 500, expires_at: 4_102_444_800
    )

    assert_equal 2, ixs.length
    ed, settle = ixs
    assert_equal PC::ED25519_PROGRAM, ed.program_id
    assert_empty ed.accounts
    assert_equal "0401", settle.data.unpack1("H*")

    # Ed25519 precompile header: pubkey @16, signature @48, message @112.
    assert_equal 112 + 48, ed.data.bytesize
    header = ed.data.byteslice(0, 16).unpack("CCv7")
    assert_equal [1, 0, 48, 0xFFFF, 16, 0xFFFF, 112, 48, 0xFFFF], header
    assert_equal ::PayCore::Solana::Base58.decode(pubkey(4)), ed.data.byteslice(16, 32)
    assert_equal signature, ed.data.byteslice(48, 64)
    assert_equal PC.voucher_message_bytes(ZERO_PUBKEY, 500, 4_102_444_800), ed.data.byteslice(112, 48)
  end

  # ---- distribute --------------------------------------------------------
  def test_distribute_empty_recipients
    ix = PC.distribute_instruction(
      channel: ZERO_PUBKEY, payer: pubkey(1), rent_payer: pubkey(5), payee: pubkey(3),
      mint: usdc_mint, token_program: PROGRAMS::TOKEN_PROGRAM
    )

    assert_equal PC::PROGRAM_ID, ix.program_id
    assert_equal "0700000000", ix.data.unpack1("H*")
    assert_equal 11, ix.accounts.length
    # First 7 accounts writable, last 4 readonly (idl distribute order).
    assert_equal [true] * 7 + [false] * 4, ix.accounts.map(&:writable)
    refute(ix.accounts.any?(&:signer))
    assert_equal PC::PROGRAM_ID, ix.accounts.last.pubkey # self_program
  end

  def test_distribute_with_recipients_appends_token_accounts
    recipients = [{recipient: pubkey(8), bps: 1_000}, {recipient: pubkey(9), bps: 250}]
    ix = PC.distribute_instruction(
      channel: ZERO_PUBKEY, payer: pubkey(1), rent_payer: pubkey(5), payee: pubkey(3),
      mint: usdc_mint, token_program: PROGRAMS::TOKEN_PROGRAM, recipients: recipients
    )

    assert_equal 13, ix.accounts.length
    expected_data = "07" + "02000000" +
      ::PayCore::Solana::Base58.decode(pubkey(8)).unpack1("H*") + "e803" +
      ::PayCore::Solana::Base58.decode(pubkey(9)).unpack1("H*") + "fa00"
    assert_equal expected_data, ix.data.unpack1("H*")
    assert(ix.accounts.last(2).all?(&:writable))
  end

  # ---- idempotent ATA create --------------------------------------------
  def test_create_idempotent_ata_instruction
    ix = PC.create_idempotent_ata_instruction(
      payer: pubkey(5), owner: pubkey(3), mint: usdc_mint, token_program: PROGRAMS::TOKEN_PROGRAM
    )

    assert_equal PC::ASSOCIATED_TOKEN_PROGRAM, ix.program_id
    assert_equal "01", ix.data.unpack1("H*")
    assert_equal [[true, true], [false, true], [false, false], [false, false], [false, false], [false, false]],
      ix.accounts.map { |a| [a.signer, a.writable] }
    expected_ata = ::PayCore::Solana::ATA.derive(owner: pubkey(3), mint: usdc_mint, token_program: PROGRAMS::TOKEN_PROGRAM)
    assert_equal expected_ata, ix.accounts[1].pubkey
  end

  # ---- PDA derivation ----------------------------------------------------
  def test_find_channel_pda_seeds
    expected = ::PayCore::Solana::PublicKey.find_program_address(
      [
        "channel".b, ::PayCore::Solana::Base58.decode(pubkey(1)), ::PayCore::Solana::Base58.decode(pubkey(3)),
        ::PayCore::Solana::Base58.decode(usdc_mint), ::PayCore::Solana::Base58.decode(pubkey(5)), [7].pack("Q<")
      ],
      PC::PROGRAM_ID
    ).first.to_s

    assert_equal expected, PC.find_channel_pda(
      payer: pubkey(1), payee: pubkey(3), mint: usdc_mint, authorized_signer: pubkey(5), salt: 7
    )
  end

  def test_find_channel_pda_salt_changes_address
    a = PC.find_channel_pda(payer: pubkey(1), payee: pubkey(3), mint: usdc_mint, authorized_signer: pubkey(5), salt: 1)
    b = PC.find_channel_pda(payer: pubkey(1), payee: pubkey(3), mint: usdc_mint, authorized_signer: pubkey(5), salt: 2)

    refute_equal a, b
  end

  def test_find_event_authority_pda_seeds
    expected = ::PayCore::Solana::PublicKey.find_program_address(["event_authority".b], PC::PROGRAM_ID).first.to_s

    assert_equal expected, PC.find_event_authority_pda
  end

  # ---- channel decode ----------------------------------------------------
  def test_decode_channel_round_trip
    data = [9, 1, 254, PC::STATUS_OPEN].pack("C4") +
      [7].pack("Q<") + [1_000_000].pack("Q<") + [50_000].pack("Q<") + [40_000].pack("Q<") +
      [123].pack("q<") + [0].pack("q<") + [900].pack("V") +
      PC::EMPTY_DISTRIBUTION_HASH +
      ::PayCore::Solana::Base58.decode(pubkey(1)) + ::PayCore::Solana::Base58.decode(pubkey(3)) +
      ::PayCore::Solana::Base58.decode(pubkey(5)) + ::PayCore::Solana::Base58.decode(usdc_mint) +
      ::PayCore::Solana::Base58.decode(pubkey(5))

    channel = PC.decode_channel(data)

    assert_equal 9, channel.discriminator
    assert_equal PC::STATUS_OPEN, channel.status
    assert_equal 7, channel.salt
    assert_equal 1_000_000, channel.deposit
    assert_equal 50_000, channel.settled
    assert_equal 40_000, channel.payout_watermark
    assert_equal 123, channel.closure_started_at
    assert_equal 900, channel.grace_period
    assert_equal PC::EMPTY_DISTRIBUTION_HASH, channel.distribution_hash
    assert_equal pubkey(1), channel.payer
    assert_equal pubkey(3), channel.payee
    assert_equal pubkey(5), channel.authorized_signer
    assert_equal usdc_mint, channel.mint
    assert_equal pubkey(5), channel.rent_payer
  end

  def test_decode_channel_rejects_short_data
    assert_raises(ArgumentError) { PC.decode_channel("\x00".b * 100) }
  end

  def test_decode_channel_rejects_non_string
    error = assert_raises(ArgumentError) { PC.decode_channel(42) }
    assert_includes error.message, "? bytes"
  end

  def test_ed25519_rejects_oversized_message
    assert_raises(ArgumentError) do
      PC.ed25519_verify_instruction(pubkey(4), "\x00".b * 64, "\x00".b * 70_000)
    end
  end

  def test_decode_channel_tolerates_trailing_bytes
    data = ("\x00".b * PC::CHANNEL_ACCOUNT_SIZE) + ("\xFF".b * 16)

    assert_equal PC::CHANNEL_ACCOUNT_SIZE, PC::CHANNEL_ACCOUNT_SIZE
    assert_instance_of PC::Channel, PC.decode_channel(data)
  end

  # ---- constants + LE helpers -------------------------------------------
  def test_constants
    assert_equal "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX", PC::PROGRAM_ID
    assert_equal "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP", PC::TREASURY_OWNER
    assert_equal 4, PC::DISCRIMINATOR_SETTLE_AND_FINALIZE
    assert_equal 7, PC::DISCRIMINATOR_DISTRIBUTE
    assert_equal 0, PC::STATUS_OPEN
    assert_equal 248, PC::CHANNEL_ACCOUNT_SIZE
  end

  def test_little_endian_helpers
    assert_equal "0100", PC.u16_le(1).unpack1("H*")
    assert_equal "01000000", PC.u32_le(1).unpack1("H*")
    assert_equal "0100000000000000", PC.u64_le(1).unpack1("H*")
    assert_equal(-1, PC.read_i64_le(PC.i64_le(-1), 0))
    assert_equal 65_535, PC.read_u32_le(PC.u32_le(65_535), 0)
    assert_equal 2**63, PC.read_u64_le(PC.u64_le(2**63), 0)
  end

  private

  def usdc_mint
    PROGRAMS::MINTS.fetch("USDC").fetch("devnet")
  end
end
