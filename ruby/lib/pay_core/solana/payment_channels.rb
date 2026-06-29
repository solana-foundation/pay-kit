# frozen_string_literal: true

require "digest"

require_relative "base58"
require_relative "public_key"
require_relative "ata"
require_relative "mints"
require_relative "instruction"

module PayCore
  module Solana
    # Hand-written, byte-identical client for the pay-kit payment-channels
    # program — the SVM `upto` (usage-based) settlement primitive. Ruby has no
    # codama codegen target, so the channel account decoder, PDA derivations,
    # voucher preimage, distribution-hash commitment, and the settle /
    # distribute / Ed25519-precompile instruction encoders are written here by
    # hand and pinned to golden byte-vectors lifted from the Go/Rust references
    # (`go/paycore/paymentchannels/*`, `rust/crates/core/src/payment_channels.rs`).
    #
    # The bytes emitted here MUST stay identical across the language SDKs or the
    # on-chain program rejects them; the offline parity tests are the guard, the
    # live Surfpool e2e matrix is the proof.
    module PaymentChannels
      module_function

      # Canonical mainnet program id; matches the codama-generated default and
      # every PDA derivation pinned to it (go/paycore/paymentchannels/
      # paymentchannels.go:27). The issue draft's `GuoKrza…` is stale.
      PROGRAM_ID = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"

      # Ed25519 signature-verification native precompile (settlement.go:22).
      ED25519_PROGRAM = "Ed25519SigVerify111111111111111111111111111"
      # Instructions sysvar the settle_and_finalize ix reads the voucher from.
      INSTRUCTIONS_SYSVAR = "Sysvar1nstructions1111111111111111111111111"
      RENT_SYSVAR = "SysvarRent111111111111111111111111111111111"
      SYSTEM_PROGRAM = "11111111111111111111111111111111"
      ASSOCIATED_TOKEN_PROGRAM = Mints::ASSOCIATED_TOKEN_PROGRAM

      # Treasury owner baked into the deployed (mainnet-build) program;
      # distribute checks the treasury ATA against ATA(TreasuryOwner, mint,
      # token_program) (settlement.go:35-37).
      TREASURY_OWNER = "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP"

      CHANNEL_SEED = "channel"
      EVENT_AUTHORITY_SEED = "event_authority"

      # One-byte instruction discriminators (idl/payment-channels.json +
      # go/protocols/programs/paymentchannels/instruction_*.go).
      DISCRIMINATOR_SETTLE_AND_FINALIZE = 4
      DISCRIMINATOR_DISTRIBUTE = 7

      # Channel.status enum (idl channelStatus): 0 = open, 1 = finalized, 2 = closing.
      STATUS_OPEN = 0

      # Borsh `Channel` account size: a 1-byte account discriminator followed by
      # the fixed fields below. The on-chain account keeps the discriminator at
      # offset 0 (unlike the codama-py dropped-discriminator quirk), so Ruby
      # decodes from offset 0.
      CHANNEL_ACCOUNT_SIZE = 248

      # sha256 over the empty distribution preimage (u32 LE count = 0). Pinned
      # to the Go `EmptyDistributionHash` constant (protocols/x402/upto.go:794);
      # `distribution_hash([])` reproduces it.
      EMPTY_DISTRIBUTION_HASH = [
        223, 63, 97, 152, 4, 169, 47, 219, 64, 87, 25, 45, 196, 61, 215, 72,
        234, 119, 138, 220, 82, 188, 73, 140, 232, 5, 36, 192, 20, 184, 17, 25
      ].pack("C*").freeze

      # Decoded payment-channel account. Only the fields the facilitator checks
      # at verify_open + settle are surfaced; the byte offsets are the verified
      # Borsh layout (idl/payment-channels.json `channel`).
      Channel = Struct.new(
        :discriminator, :version, :bump, :status, :salt, :deposit,
        :settled, :payout_watermark, :closure_started_at, :payer_withdrawn_at,
        :grace_period, :distribution_hash, :payer, :payee, :authorized_signer,
        :mint, :rent_payer, keyword_init: true
      )

      # ---- little-endian Borsh primitives ----------------------------------
      def u16_le(value) = [value].pack("v")

      def u32_le(value) = [value].pack("V")

      def u64_le(value) = [value].pack("Q<")

      def i64_le(value) = [value].pack("q<")

      def read_u32_le(bytes, offset) = bytes.byteslice(offset, 4).unpack1("V")

      def read_u64_le(bytes, offset) = bytes.byteslice(offset, 8).unpack1("Q<")

      def read_i64_le(bytes, offset) = bytes.byteslice(offset, 8).unpack1("q<")

      # ---- PDA derivations -------------------------------------------------
      # Derive the channel PDA from
      # ["channel", payer, payee, mint, authorizedSigner, salt(u64 LE)] against
      # the channel program (paymentchannels.go:170-188). Returns base58.
      def find_channel_pda(payer:, payee:, mint:, authorized_signer:, salt:, program_id: PROGRAM_ID)
        seeds = [
          CHANNEL_SEED.b,
          Base58.decode(payer),
          Base58.decode(payee),
          Base58.decode(mint),
          Base58.decode(authorized_signer),
          u64_le(salt)
        ]
        PublicKey.find_program_address(seeds, program_id).first.to_s
      end

      # Derive the event-authority PDA from ["event_authority"]
      # (paymentchannels.go:198-207). Returns base58.
      def find_event_authority_pda(program_id: PROGRAM_ID)
        PublicKey.find_program_address([EVENT_AUTHORITY_SEED.b], program_id).first.to_s
      end

      # ---- voucher + distribution commitment -------------------------------
      # 48-byte voucher preimage signed by the authorized signer:
      # channelId(32) || cumulativeAmount(u64 LE) || expiresAt(i64 LE).
      # Exactly the Borsh VoucherArgs layout (paymentchannels.go:149-159).
      def voucher_message_bytes(channel_id, cumulative, expires_at)
        Base58.decode(channel_id) + u64_le(cumulative) + i64_le(expires_at)
      end

      # sha256 of the distribution preimage
      # count(u32 LE) || [recipient(32) || bps(u16 LE)]…, byte-for-byte what the
      # on-chain program commits at open (rust payment_channels.rs:244-257).
      # MUST stay sha256: the program rejects a mismatch with
      # InvalidDistributionHash. `recipients` is an Array of
      # `{recipient: base58, bps: Integer}`.
      def distribution_hash(recipients)
        preimage = u32_le(recipients.length)
        recipients.each do |entry|
          preimage += Base58.decode(entry.fetch(:recipient)) + u16_le(entry.fetch(:bps))
        end
        Digest::SHA256.digest(preimage)
      end

      # ---- account decode --------------------------------------------------
      # Decode a payment-channel account from raw on-chain bytes.
      def decode_channel(data)
        unless data.is_a?(String) && data.bytesize >= CHANNEL_ACCOUNT_SIZE
          raise ArgumentError, "channel account is #{data.respond_to?(:bytesize) ? data.bytesize : "?"} bytes, want >= #{CHANNEL_ACCOUNT_SIZE}"
        end

        Channel.new(
          discriminator: data.getbyte(0),
          version: data.getbyte(1),
          bump: data.getbyte(2),
          status: data.getbyte(3),
          salt: read_u64_le(data, 4),
          deposit: read_u64_le(data, 12),
          settled: read_u64_le(data, 20),
          payout_watermark: read_u64_le(data, 28),
          closure_started_at: read_i64_le(data, 36),
          payer_withdrawn_at: read_i64_le(data, 44),
          grace_period: read_u32_le(data, 52),
          distribution_hash: data.byteslice(56, 32),
          payer: Base58.encode(data.byteslice(88, 32)),
          payee: Base58.encode(data.byteslice(120, 32)),
          authorized_signer: Base58.encode(data.byteslice(152, 32)),
          mint: Base58.encode(data.byteslice(184, 32)),
          rent_payer: Base58.encode(data.byteslice(216, 32))
        )
      end

      # ---- instruction encoders --------------------------------------------
      # Ed25519 precompile instruction verifying `signature` over `message`
      # against `authorized_signer`, with the signature material embedded in
      # the instruction data (every instruction-index field is 0xFFFF, "current
      # instruction"). Fixed header: pubkey @16, signature @48, message @112
      # (settlement.go:45-69).
      def ed25519_verify_instruction(authorized_signer, signature, message)
        public_key_offset = 16
        signature_offset = public_key_offset + 32   # 48
        message_data_offset = signature_offset + 64 # 112
        current_instruction = 0xFFFF

        if message.bytesize > 0xFFFF
          raise ArgumentError, "voucher message too long: #{message.bytesize} bytes"
        end

        header = [
          1, 0,                       # num_signatures, padding
          signature_offset, current_instruction,
          public_key_offset, current_instruction,
          message_data_offset, message.bytesize, current_instruction
        ].pack("CCv7")

        data = header + Base58.decode(authorized_signer) + signature + message
        PreparedInstruction.new(ED25519_PROGRAM, [], data)
      end

      # Build the settle_and_finalize sequence. When a voucher signature is
      # present an Ed25519 precompile instruction over the canonical 48-byte
      # voucher message precedes settle_and_finalize (which reads it through the
      # instructions sysvar) and hasVoucher = 1; otherwise a single
      # voucherless settle_and_finalize closes the channel with a full refund
      # (settlement.go:155-188).
      def settle_and_finalize_instructions(merchant:, channel:, authorized_signer:, signature:, cumulative:, expires_at:, program_id: PROGRAM_ID)
        instructions = []
        has_voucher = 0
        unless signature.nil?
          message = voucher_message_bytes(channel, cumulative, expires_at)
          instructions << ed25519_verify_instruction(authorized_signer, signature, message)
          has_voucher = 1
        end

        # disc(4) || SettleAndFinalizeArgs{ hasVoucher: u8 }.
        settle = PreparedInstruction.new(
          program_id,
          [
            AccountMeta.signer_readonly(merchant),
            AccountMeta.writable(channel),
            AccountMeta.readonly(INSTRUCTIONS_SYSVAR)
          ],
          [DISCRIMINATOR_SETTLE_AND_FINALIZE, has_voucher].pack("C2")
        )
        instructions << settle
        instructions
      end

      # Build the distribute instruction: the 11 fixed accounts in the exact
      # order the program expects, plus one writable token account per split
      # recipient. `upto` settles empty-recipient channels, so `recipients`
      # defaults to none — the payer is refunded the unsettled remainder and the
      # payee/treasury receive the settled split (settlement.go:230-296).
      def distribute_instruction(channel:, payer:, rent_payer:, payee:, mint:, token_program:, treasury: TREASURY_OWNER, recipients: [], program_id: PROGRAM_ID)
        channel_token = ATA.derive(owner: channel, mint: mint, token_program: token_program)
        payer_token = ATA.derive(owner: payer, mint: mint, token_program: token_program)
        payee_token = ATA.derive(owner: payee, mint: mint, token_program: token_program)
        treasury_token = ATA.derive(owner: treasury, mint: mint, token_program: token_program)
        event_authority = find_event_authority_pda(program_id: program_id)

        accounts = [
          AccountMeta.writable(channel),
          AccountMeta.writable(payer),
          AccountMeta.writable(rent_payer),
          AccountMeta.writable(channel_token),
          AccountMeta.writable(payer_token),
          AccountMeta.writable(payee_token),
          AccountMeta.writable(treasury_token),
          AccountMeta.readonly(mint),
          AccountMeta.readonly(token_program),
          AccountMeta.readonly(event_authority),
          AccountMeta.readonly(program_id)
        ]

        data = [DISCRIMINATOR_DISTRIBUTE].pack("C") + u32_le(recipients.length)
        recipients.each do |entry|
          recipient = entry.fetch(:recipient)
          accounts << AccountMeta.writable(ATA.derive(owner: recipient, mint: mint, token_program: token_program))
          data += Base58.decode(recipient) + u16_le(entry.fetch(:bps))
        end

        PreparedInstruction.new(program_id, accounts, data)
      end

      # Idempotent associated-token-account create. The settle transaction
      # creates the payee + treasury ATAs before distribute so the transfer
      # targets exist; idempotent (data = [1]) so an already-present ATA is a
      # no-op rather than a failure (solanatx.go:73-91).
      def create_idempotent_ata_instruction(payer:, owner:, mint:, token_program:)
        ata = ATA.derive(owner: owner, mint: mint, token_program: token_program)
        PreparedInstruction.new(
          ASSOCIATED_TOKEN_PROGRAM,
          [
            AccountMeta.signer_writable(payer),
            AccountMeta.writable(ata),
            AccountMeta.readonly(owner),
            AccountMeta.readonly(mint),
            AccountMeta.readonly(SYSTEM_PROGRAM),
            AccountMeta.readonly(token_program)
          ],
          [1].pack("C")
        )
      end
    end
  end
end
