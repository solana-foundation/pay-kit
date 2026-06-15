package com.solana.paykit.paycore

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Byte-for-byte parity oracles for the Kotlin instruction builders.
 *
 * Each golden value is derived directly from the Rust spine:
 *
 * - `rust/src/client/charge.rs` (transfer_checked_ix, compute_unit_*_ix,
 *   create_associated_token_account_idempotent, push_memo_instruction,
 *   system_instruction::transfer).
 * - `rust/src/protocol/solana.rs::programs` (program ids).
 *
 * Any Kotlin output that diverges from these by even one byte breaks the
 * cross-language wire-format contract.
 */
class InstructionsTest {
    private val payer = "5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK"
    private val owner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
    private val mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    private val authority = "DczFR3PHCAdHFkVKzM6gv6JNXAJjGy5XhSqxKtfBQ8d8"
    private val source = "9wZW7AKEAQiV8DSBdvLudo3SkuxBwh3KrFP1nN8ePoX8"
    private val destination = "8L8KXxqAdptT2vWzkAesyRwk6yJ6BPBuwzdt8nFb1ehu"

    // ── Program ids ──

    @Test
    fun programIdsMatchRustSpine() {
        // From rust/src/protocol/solana.rs::programs.
        assertEquals("11111111111111111111111111111111", Programs.SYSTEM_PROGRAM)
        assertEquals("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", Programs.TOKEN_PROGRAM)
        assertEquals("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", Programs.TOKEN_2022_PROGRAM)
        assertEquals("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", Programs.ASSOCIATED_TOKEN_PROGRAM)
        assertEquals("ComputeBudget111111111111111111111111111111", Programs.COMPUTE_BUDGET_PROGRAM)
        assertEquals("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", Programs.MEMO_PROGRAM)
    }

    // ── System program transfer ──

    @Test
    fun systemTransferMatchesRustWireFormat() {
        // Rust: solana_system_interface::instruction::transfer encodes the
        // transfer variant of SystemInstruction. Discriminator 2 in
        // little-endian u32, then lamports as u64 LE.
        val ix = Instructions.systemTransfer(payer, owner, 1_000_000L)

        assertEquals(Programs.SYSTEM_PROGRAM, ix.programId)
        assertEquals(2, ix.accounts.size)
        assertEquals(AccountMeta.writable(payer, signer = true), ix.accounts[0])
        assertEquals(AccountMeta.writable(owner), ix.accounts[1])
        assertContentEquals(
            byteArrayOf(
                0x02, 0x00, 0x00, 0x00, // u32 little-endian discriminator
                0x40.toByte(), 0x42.toByte(), 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, // 1_000_000 LE u64
            ),
            ix.data,
        )
    }

    @Test
    fun systemTransferRejectsNegativeLamports() {
        assertFailsWith<IllegalArgumentException> {
            Instructions.systemTransfer(payer, owner, -1L)
        }
    }

    // ── SPL transferChecked ──

    @Test
    fun transferCheckedMatchesRustWireFormat() {
        // Rust transfer_checked_ix: data = [12u8, amount u64 LE, decimals u8].
        // Test parameters chosen to mirror Rust transfer_checked_ix_structure
        // (amount = 42_000, decimals = 6).
        val ix = Instructions.transferChecked(
            tokenProgram = Programs.TOKEN_PROGRAM,
            source = source,
            mint = mint,
            destination = destination,
            authority = authority,
            amount = 42_000L,
            decimals = 6,
        )

        assertEquals(Programs.TOKEN_PROGRAM, ix.programId)
        assertEquals(4, ix.accounts.size)
        // source writable not signer, mint read-only, dest writable, authority signer read-only.
        assertTrue(ix.accounts[0].isWritable)
        assertFalse(ix.accounts[0].isSigner)
        assertFalse(ix.accounts[1].isWritable)
        assertTrue(ix.accounts[2].isWritable)
        assertTrue(ix.accounts[3].isSigner)
        assertFalse(ix.accounts[3].isWritable)
        assertContentEquals(
            byteArrayOf(
                12, // TransferChecked discriminator
                0x10, 0xa4.toByte(), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 42_000 u64 LE
                6, // decimals
            ),
            ix.data,
        )
    }

    @Test
    fun transferCheckedWorksForToken2022Program() {
        val ix = Instructions.transferChecked(
            tokenProgram = Programs.TOKEN_2022_PROGRAM,
            source = source,
            mint = mint,
            destination = destination,
            authority = authority,
            amount = 1L,
            decimals = 9,
        )
        assertEquals(Programs.TOKEN_2022_PROGRAM, ix.programId)
    }

    @Test
    fun transferCheckedRejectsOutOfRangeDecimals() {
        assertFailsWith<IllegalArgumentException> {
            Instructions.transferChecked(
                tokenProgram = Programs.TOKEN_PROGRAM,
                source = source,
                mint = mint,
                destination = destination,
                authority = authority,
                amount = 0L,
                decimals = 256,
            )
        }
    }

    // ── Associated token account ──

    @Test
    fun createAssociatedTokenAccountIdempotentMatchesRust() {
        val ata = "11111111111111111111111111111112" // synthetic
        val ix = Instructions.createAssociatedTokenAccountIdempotent(
            payer = payer,
            ata = ata,
            owner = owner,
            mint = mint,
            tokenProgram = Programs.TOKEN_PROGRAM,
        )

        assertEquals(Programs.ASSOCIATED_TOKEN_PROGRAM, ix.programId)
        assertEquals(6, ix.accounts.size)
        assertContentEquals(byteArrayOf(0x01), ix.data)
        // Order from rust create_associated_token_account_idempotent: payer, ata, owner, mint, system, token program.
        assertEquals(payer, ix.accounts[0].pubkey)
        assertTrue(ix.accounts[0].isSigner)
        assertTrue(ix.accounts[0].isWritable)
        assertEquals(ata, ix.accounts[1].pubkey)
        assertTrue(ix.accounts[1].isWritable)
        assertEquals(owner, ix.accounts[2].pubkey)
        assertFalse(ix.accounts[2].isSigner)
        assertFalse(ix.accounts[2].isWritable)
        assertEquals(mint, ix.accounts[3].pubkey)
        assertEquals(Programs.SYSTEM_PROGRAM, ix.accounts[4].pubkey)
        assertEquals(Programs.TOKEN_PROGRAM, ix.accounts[5].pubkey)
    }

    // ── Compute budget ──

    @Test
    fun setComputeUnitLimitMatchesRust() {
        // compute_unit_limit_ix: data = [2u8, units u32 LE]. 200_000 = 0x000_30D40.
        val ix = Instructions.setComputeUnitLimit(200_000)
        assertEquals(Programs.COMPUTE_BUDGET_PROGRAM, ix.programId)
        assertEquals(0, ix.accounts.size)
        assertContentEquals(
            byteArrayOf(0x02, 0x40.toByte(), 0x0d, 0x03, 0x00),
            ix.data,
        )
    }

    @Test
    fun setComputeUnitPriceMatchesRust() {
        // compute_unit_price_ix: data = [3u8, micro_lamports u64 LE].
        val ix = Instructions.setComputeUnitPrice(1L)
        assertEquals(Programs.COMPUTE_BUDGET_PROGRAM, ix.programId)
        assertContentEquals(
            byteArrayOf(0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            ix.data,
        )
    }

    // ── Memo ──

    @Test
    fun memoEncodesUtf8Bytes() {
        val ix = Instructions.memo("order-123")
        assertEquals(Programs.MEMO_PROGRAM, ix.programId)
        assertEquals(0, ix.accounts.size)
        assertContentEquals("order-123".encodeToByteArray(), ix.data)
    }

    @Test
    fun memoRejectsAboveLimit() {
        // Rust push_memo_instruction caps memos at 566 bytes.
        val tooLong = "x".repeat(567)
        assertFailsWith<MppException.MemoTooLong> { Instructions.memo(tooLong) }
    }

    @Test
    fun memoAtLimitIsAccepted() {
        val borderline = "x".repeat(566)
        val ix = Instructions.memo(borderline)
        assertEquals(566, ix.data.size)
    }

    // ── Internal encoders ──

    @Test
    fun encodeUInt64LERoundTrip() {
        val buffer = ByteArray(8)
        Instructions.encodeUInt64LE(0xDEAD_BEEF_CAFE_F00DuL, buffer, 0)
        assertContentEquals(
            byteArrayOf(
                0x0d, 0xf0.toByte(), 0xfe.toByte(), 0xca.toByte(),
                0xef.toByte(), 0xbe.toByte(), 0xad.toByte(), 0xde.toByte(),
            ),
            buffer,
        )
    }

    // ── Unsigned u64 BigInteger overloads (main medium) ──

    @Test
    fun systemTransferBigIntegerEncodesFullU64() {
        // u64 max = 0xFFFF...FFFF; a signed Long cannot hold it. The BigInteger
        // overload must write the exact little-endian u64 bit pattern.
        val u64Max = java.math.BigInteger.ONE.shiftLeft(64).subtract(java.math.BigInteger.ONE)
        val ix = Instructions.systemTransfer(payer, owner, u64Max)
        assertContentEquals(
            byteArrayOf(
                0x02, 0x00, 0x00, 0x00, // discriminator
                0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(),
                0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), // u64 max LE
            ),
            ix.data,
        )
    }

    @Test
    fun systemTransferBigIntegerMatchesLongForSmallValues() {
        val long = Instructions.systemTransfer(payer, owner, 1_000_000L)
        val big = Instructions.systemTransfer(payer, owner, java.math.BigInteger.valueOf(1_000_000L))
        assertContentEquals(long.data, big.data)
    }

    @Test
    fun transferCheckedBigIntegerEncodesAboveSignedLongMax() {
        // 2^63 is one past Long.MAX_VALUE; the unsigned overload must encode it
        // as 0x00...00_80 (LE), proving no signed truncation.
        val twoPow63 = java.math.BigInteger.ONE.shiftLeft(63)
        val ix = Instructions.transferChecked(
            tokenProgram = Programs.TOKEN_PROGRAM,
            source = source,
            mint = mint,
            destination = destination,
            authority = authority,
            amount = twoPow63,
            decimals = 6,
        )
        assertContentEquals(
            byteArrayOf(
                12, // discriminator
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80.toByte(), // 2^63 LE u64
                6, // decimals
            ),
            ix.data,
        )
    }

    @Test
    fun bigIntegerOverloadsRejectNegativeAndOversized() {
        assertFailsWith<IllegalArgumentException> {
            Instructions.systemTransfer(payer, owner, java.math.BigInteger.valueOf(-1L))
        }
        assertFailsWith<IllegalArgumentException> {
            Instructions.transferChecked(
                tokenProgram = Programs.TOKEN_PROGRAM,
                source = source,
                mint = mint,
                destination = destination,
                authority = authority,
                amount = java.math.BigInteger.ONE.shiftLeft(64), // 2^64, out of u64 range
                decimals = 6,
            )
        }
    }

    @Test
    fun encodeUInt32LERoundTrip() {
        val buffer = ByteArray(4)
        Instructions.encodeUInt32LE(0xDEAD_BEEFu, buffer, 0)
        assertContentEquals(
            byteArrayOf(0xef.toByte(), 0xbe.toByte(), 0xad.toByte(), 0xde.toByte()),
            buffer,
        )
    }
}
