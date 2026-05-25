package com.solana.mpp.crypto

import com.solana.mpp.protocol.MppException

/**
 * Solana program identifiers used by the MPP charge client.
 *
 * Sourced byte-for-byte from the Rust spine at
 * `rust/src/protocol/solana.rs` (`programs` module) so the Kotlin
 * builders pick the same on-chain programs as the reference SDK.
 */
object Programs {
    const val SYSTEM_PROGRAM = "11111111111111111111111111111111"
    const val TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    const val TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
    const val ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
    const val COMPUTE_BUDGET_PROGRAM = "ComputeBudget111111111111111111111111111111"
    const val MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
}

/** Reference to a Solana account included in an instruction. */
data class AccountMeta(
    /** Base58-encoded account public key (32 byte). */
    val pubkey: String,
    /** True when the account is required to sign the transaction. */
    val isSigner: Boolean,
    /** True when the account is written to by the instruction. */
    val isWritable: Boolean,
) {
    companion object {
        /** Writable account, optionally a signer. */
        fun writable(pubkey: String, signer: Boolean = false): AccountMeta =
            AccountMeta(pubkey = pubkey, isSigner = signer, isWritable = true)

        /** Read-only account, optionally a signer. */
        fun readOnly(pubkey: String, signer: Boolean = false): AccountMeta =
            AccountMeta(pubkey = pubkey, isSigner = signer, isWritable = false)
    }
}

/** Solana program invocation. */
data class Instruction(
    val programId: String,
    val accounts: List<AccountMeta>,
    val data: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Instruction) return false
        return programId == other.programId &&
            accounts == other.accounts &&
            data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = programId.hashCode()
        result = 31 * result + accounts.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}

/**
 * Builders for the Solana on-chain programs the MPP charge intent uses.
 *
 * Every builder produces byte-for-byte identical instruction data to the
 * Rust spine. Parity oracles are documented per builder; the matching
 * Kotlin tests assert equality against the Rust source-derived golden
 * values.
 */
object Instructions {
    // ── System program ──

    /**
     * SystemProgram::transfer — moves `lamports` from `from` to `to`.
     *
     * Wire format: 4 byte little-endian discriminator `0x02 0x00 0x00 0x00`
     * followed by `lamports` as u64 little-endian.
     * Reference: `solana_system_interface::instruction::transfer`, used by
     * `rust/src/client/charge.rs:324`.
     */
    fun systemTransfer(from: String, to: String, lamports: Long): Instruction {
        require(lamports >= 0) { "lamports must be non-negative" }
        val data = ByteArray(4 + 8)
        // Discriminator 2 in little-endian u32.
        data[0] = 0x02
        encodeUInt64LE(lamports.toULong(), data, 4)
        return Instruction(
            programId = Programs.SYSTEM_PROGRAM,
            accounts = listOf(
                AccountMeta.writable(from, signer = true),
                AccountMeta.writable(to),
            ),
            data = data,
        )
    }

    // ── SPL token (and Token-2022, same wire format) ──

    /**
     * SPL token TransferChecked — moves SPL units with mint + decimals
     * cross-checked on chain.
     *
     * Wire format: 1 byte discriminator `0x0c` (12) then `amount` u64
     * little-endian then `decimals` u8.
     * Reference: `rust/src/client/charge.rs::transfer_checked_ix` at
     * line 498.
     */
    fun transferChecked(
        tokenProgram: String,
        source: String,
        mint: String,
        destination: String,
        authority: String,
        amount: Long,
        decimals: Int,
    ): Instruction {
        require(amount >= 0) { "amount must be non-negative" }
        require(decimals in 0..255) { "decimals must fit in u8" }
        val data = ByteArray(1 + 8 + 1)
        data[0] = 12
        encodeUInt64LE(amount.toULong(), data, 1)
        data[9] = decimals.toByte()
        return Instruction(
            programId = tokenProgram,
            accounts = listOf(
                AccountMeta.writable(source),
                AccountMeta.readOnly(mint),
                AccountMeta.writable(destination),
                AccountMeta.readOnly(authority, signer = true),
            ),
            data = data,
        )
    }

    // ── Associated token account ──

    /**
     * Associated Token Account program CreateIdempotent instruction.
     *
     * Wire format: 1 byte discriminator `0x01`. Accounts in fixed order:
     * payer (signer, writable), ata (writable), owner (read-only), mint
     * (read-only), system program (read-only), token program (read-only).
     * Reference: `rust/src/client/charge.rs::create_associated_token_account_idempotent`
     * at line 474.
     */
    fun createAssociatedTokenAccountIdempotent(
        payer: String,
        ata: String,
        owner: String,
        mint: String,
        tokenProgram: String,
    ): Instruction =
        Instruction(
            programId = Programs.ASSOCIATED_TOKEN_PROGRAM,
            accounts = listOf(
                AccountMeta.writable(payer, signer = true),
                AccountMeta.writable(ata),
                AccountMeta.readOnly(owner),
                AccountMeta.readOnly(mint),
                AccountMeta.readOnly(Programs.SYSTEM_PROGRAM),
                AccountMeta.readOnly(tokenProgram),
            ),
            data = byteArrayOf(0x01),
        )

    // ── Compute budget ──

    /**
     * ComputeBudget SetComputeUnitLimit.
     *
     * Wire format: 1 byte discriminator `0x02` then `units` u32 little-endian.
     * Reference: `rust/src/client/charge.rs::compute_unit_limit_ix` at
     * line 303.
     */
    fun setComputeUnitLimit(units: Int): Instruction {
        require(units >= 0) { "units must be non-negative" }
        val data = ByteArray(1 + 4)
        data[0] = 0x02
        encodeUInt32LE(units.toUInt(), data, 1)
        return Instruction(
            programId = Programs.COMPUTE_BUDGET_PROGRAM,
            accounts = emptyList(),
            data = data,
        )
    }

    /**
     * ComputeBudget SetComputeUnitPrice (price in micro-lamports).
     *
     * Wire format: 1 byte discriminator `0x03` then `microLamports` u64
     * little-endian.
     * Reference: `rust/src/client/charge.rs::compute_unit_price_ix` at
     * line 292.
     */
    fun setComputeUnitPrice(microLamports: Long): Instruction {
        require(microLamports >= 0) { "microLamports must be non-negative" }
        val data = ByteArray(1 + 8)
        data[0] = 0x03
        encodeUInt64LE(microLamports.toULong(), data, 1)
        return Instruction(
            programId = Programs.COMPUTE_BUDGET_PROGRAM,
            accounts = emptyList(),
            data = data,
        )
    }

    // ── Memo ──

    /**
     * Memo program instruction. The instruction data is the UTF-8 bytes of
     * the memo. The hard limit of 566 bytes matches the Rust spine
     * (`push_memo_instruction` in `rust/src/client/charge.rs:421`).
     */
    fun memo(memo: String): Instruction {
        val data = memo.encodeToByteArray()
        if (data.size > 566) {
            throw MppException.MemoTooLong(data.size)
        }
        return Instruction(
            programId = Programs.MEMO_PROGRAM,
            accounts = emptyList(),
            data = data,
        )
    }

    // ── Helpers ──

    internal fun encodeUInt32LE(value: UInt, out: ByteArray, offset: Int) {
        out[offset] = (value and 0xffu).toByte()
        out[offset + 1] = ((value shr 8) and 0xffu).toByte()
        out[offset + 2] = ((value shr 16) and 0xffu).toByte()
        out[offset + 3] = ((value shr 24) and 0xffu).toByte()
    }

    internal fun encodeUInt64LE(value: ULong, out: ByteArray, offset: Int) {
        var shift = 0
        for (i in 0..7) {
            out[offset + i] = ((value shr shift) and 0xffuL).toByte()
            shift += 8
        }
    }
}
