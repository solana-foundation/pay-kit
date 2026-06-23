package com.solana.paykit.paycore

import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * Client-side payment-channels primitives: PDA/ATA derivation, the 48-byte
 * voucher preimage, and the `open` instruction + payer-signed (operator-fee-
 * payer-unsigned) open transaction the session client broadcasts via the
 * operator.
 *
 * Mirrors the client-facing subset of `solana_pay_core::payment_channels`
 * (`rust/crates/core/src/payment_channels.rs`). The server-only primitives
 * (ed25519 verify precompile, settle/finalize/distribute, the BLAKE3
 * distribution hash) are intentionally omitted: this SDK is client-only and the
 * channel `open` passes its recipients inline rather than hashed.
 */
object PaymentChannels {
    /** Canonical payment-channels program ID deployed to Surfnet. */
    const val PROGRAM_ID = "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc"

    /** Rent sysvar account. */
    const val RENT_SYSVAR_ID = "SysvarRent111111111111111111111111111111111"

    /** Default payment-channel close grace period, in seconds. */
    const val DEFAULT_GRACE_PERIOD_SECONDS: UInt = 900u

    private const val OPEN_DISCRIMINATOR: Byte = 1
    private val CHANNEL_SEED = "channel".encodeToByteArray()
    private val EVENT_AUTHORITY_SEED = "event_authority".encodeToByteArray()

    /** A recipient split: `bps` basis points of the settled balance. */
    data class Distribution(val recipient: PublicKey, val bps: Int) {
        init {
            require(bps in 0..0xFFFF) { "bps must fit in u16 (got $bps)" }
        }
    }

    /** Inputs to the channel `open` instruction. */
    data class OpenChannelParams(
        val payer: PublicKey,
        val payee: PublicKey,
        val mint: PublicKey,
        val authorizedSigner: PublicKey,
        val salt: ULong,
        val deposit: ULong,
        val gracePeriod: UInt,
        val recipients: List<Distribution>,
        val tokenProgram: PublicKey,
        val programId: PublicKey,
    )

    /** Derived channel PDA + base64 (payer-signed, fee-payer-unsigned) open tx. */
    data class OpenTransaction(val channelId: PublicKey, val transaction: String)

    // ── Voucher preimage ──

    /**
     * The 48-byte Ed25519 voucher preimage:
     * `channelId(32) || cumulativeAmount(u64 LE) || expiresAt(i64 LE)`.
     */
    fun voucherMessageBytes(channelId: String, cumulative: ULong, expiresAt: Long): ByteArray {
        val channel = PublicKey.fromBase58(channelId)
        val out = ByteArray(48)
        System.arraycopy(channel.bytes, 0, out, 0, 32)
        System.arraycopy(u64Le(cumulative), 0, out, 32, 8)
        // i64 little-endian shares the two's-complement bit pattern of u64 LE.
        System.arraycopy(u64Le(expiresAt.toULong()), 0, out, 40, 8)
        return out
    }

    // ── PDA derivation ──

    fun findChannelPda(
        payer: PublicKey,
        payee: PublicKey,
        mint: PublicKey,
        authorizedSigner: PublicKey,
        salt: ULong,
        programId: PublicKey,
    ): PublicKey {
        val seeds = listOf(
            CHANNEL_SEED,
            payer.bytes,
            payee.bytes,
            mint.bytes,
            authorizedSigner.bytes,
            u64Le(salt),
        )
        return Pda.findProgramAddress(seeds, programId).first
    }

    fun findEventAuthorityPda(programId: PublicKey): PublicKey =
        Pda.findProgramAddress(listOf(EVENT_AUTHORITY_SEED), programId).first

    /** Random u64 channel salt so concurrent opens derive distinct channel PDAs. */
    fun uniqueSalt(): ULong {
        val bytes = Ed25519.generateSeed() // 32 CSPRNG bytes; take the low 8.
        var value = 0uL
        for (i in 0..7) value = value or (bytes[i].toULong() and 0xffuL shl (8 * i))
        return value
    }

    // ── Open instruction + transaction ──

    fun buildOpenInstruction(params: OpenChannelParams): Instruction {
        val channel = findChannelPda(
            params.payer, params.payee, params.mint, params.authorizedSigner, params.salt, params.programId
        )
        val payerTokenAccount = Pda.associatedTokenAddress(params.payer, params.mint, params.tokenProgram)
        val channelTokenAccount = Pda.associatedTokenAddress(channel, params.mint, params.tokenProgram)
        val eventAuthority = findEventAuthorityPda(params.programId)

        // Account order matches the codama-generated `Open` builder exactly.
        val accounts = listOf(
            AccountMeta.writable(params.payer.toBase58(), signer = true),
            AccountMeta.readOnly(params.payee.toBase58()),
            AccountMeta.readOnly(params.mint.toBase58()),
            AccountMeta.readOnly(params.authorizedSigner.toBase58()),
            AccountMeta.writable(channel.toBase58()),
            AccountMeta.writable(payerTokenAccount.toBase58()),
            AccountMeta.writable(channelTokenAccount.toBase58()),
            AccountMeta.readOnly(params.tokenProgram.toBase58()),
            AccountMeta.readOnly(Programs.SYSTEM_PROGRAM),
            AccountMeta.readOnly(RENT_SYSVAR_ID),
            AccountMeta.readOnly(Programs.ASSOCIATED_TOKEN_PROGRAM),
            AccountMeta.readOnly(eventAuthority.toBase58()),
            AccountMeta.readOnly(params.programId.toBase58()),
        )

        // data = discriminator(1) || borsh(OpenArgs { salt, deposit, gracePeriod, recipients }).
        val data = ByteArrayOutputStream()
        data.write(byteArrayOf(OPEN_DISCRIMINATOR))
        data.write(u64Le(params.salt))
        data.write(u64Le(params.deposit))
        data.write(u32Le(params.gracePeriod))
        data.write(u32Le(params.recipients.size.toUInt()))
        for (entry in params.recipients) {
            data.write(entry.recipient.bytes)
            data.write(u16Le(entry.bps))
        }

        return Instruction(programId = params.programId.toBase58(), accounts = accounts, data = data.toByteArray())
    }

    /**
     * Build a payer-signed (fee-payer-unsigned) channel `open` transaction. The
     * `payer` signs to authorize the deposit; the `feePayer` (operator) slot is
     * left empty for the server to co-sign before broadcast.
     */
    fun buildOpenTransaction(
        payer: SolanaSigner,
        payee: PublicKey,
        mint: PublicKey,
        authorizedSigner: PublicKey,
        salt: ULong,
        deposit: ULong,
        gracePeriod: UInt,
        recipients: List<Distribution>,
        tokenProgram: PublicKey,
        programId: PublicKey,
        feePayer: PublicKey,
        recentBlockhash: ByteArray,
    ): OpenTransaction {
        val payerPubkey = PublicKey(payer.publicKeyBytes)
        val params = OpenChannelParams(
            payer = payerPubkey, payee = payee, mint = mint, authorizedSigner = authorizedSigner,
            salt = salt, deposit = deposit, gracePeriod = gracePeriod, recipients = recipients,
            tokenProgram = tokenProgram, programId = programId,
        )
        val channelId = findChannelPda(payerPubkey, payee, mint, authorizedSigner, salt, programId)
        val instruction = buildOpenInstruction(params)
        val message = Transaction.buildLegacyMessage(feePayer, recentBlockhash, listOf(instruction))
        val signature = payer.sign(message.serialize())
        require(signature.size == 64) { "open signature must be 64 bytes (got ${signature.size})" }
        val signerIndex = message.accountKeys.indexOfFirst { it.bytes.contentEquals(payerPubkey.bytes) }
        if (signerIndex < 0) {
            throw MppException.InvalidTransaction("payer is not in the open transaction account list")
        }
        val signatures = MutableList<ByteArray?>(message.header.numRequiredSignatures) { null }
        // The payer must land in the signer prefix of the account list; guard the
        // index so a non-signer slot throws instead of going out of bounds.
        if (signerIndex >= signatures.size) {
            throw MppException.InvalidTransaction("payer signer index $signerIndex is outside the required-signer range")
        }
        signatures[signerIndex] = signature
        val txBytes = Transaction.serializeLegacyTransaction(message, signatures)
        return OpenTransaction(channelId = channelId, transaction = Base64.getEncoder().encodeToString(txBytes))
    }

    // ── Little-endian helpers ──

    private fun u64Le(value: ULong): ByteArray {
        val out = ByteArray(8)
        var shift = 0
        for (i in 0..7) {
            out[i] = ((value shr shift) and 0xffuL).toByte()
            shift += 8
        }
        return out
    }

    private fun u32Le(value: UInt): ByteArray {
        val out = ByteArray(4)
        out[0] = (value and 0xffu).toByte()
        out[1] = ((value shr 8) and 0xffu).toByte()
        out[2] = ((value shr 16) and 0xffu).toByte()
        out[3] = ((value shr 24) and 0xffu).toByte()
        return out
    }

    private fun u16Le(value: Int): ByteArray {
        val v = value.toUInt()
        return byteArrayOf((v and 0xffu).toByte(), ((v shr 8) and 0xffu).toByte())
    }
}
