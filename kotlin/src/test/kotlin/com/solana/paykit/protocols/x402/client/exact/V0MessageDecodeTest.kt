package com.solana.paykit.protocols.x402.client.exact

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.Mints
import com.solana.paykit.paycore.Network
import com.solana.paykit.paycore.Pda
import com.solana.paykit.paycore.Programs
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.protocols.x402.exact.X402AcceptsEntry
import com.solana.paykit.protocols.x402.exact.X402Extra
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Decode-and-assert tests for the built v0 transaction.
 *
 * Unlike [BuildPaymentTest] (which substring-searches the wire bytes), these
 * tests fully parse the v0 message and assert structure the rust verifier
 * (``rust/crates/x402/src/protocol/schemes/exact/verify.rs``) checks:
 *
 *  - instruction order: ComputeUnitLimit, ComputeUnitPrice, transferChecked, [memo]
 *  - transferChecked account indices resolve to [source, mint, dest, authority]
 *  - destination == ATA(payTo, mint, tokenProgram)
 *  - the fee-payer signature slot is left empty (cosigned server-side)
 *  - numRequiredSignatures == 2 when the offer carries a distinct feePayer
 *
 * Also pins a golden v0 SPL byte vector so the web3-solana-built
 * transferChecked layout cannot drift silently.
 */
class V0MessageDecodeTest {

    private val seed = ByteArray(32) { 0x42 }
    private val signer = MemorySigner.fromSeed(seed)
    private val signerKey = PublicKey(signer.publicKeyBytes)

    private val payTo = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
    private val feePayer = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ"
    // Base58 of 32 0x07 bytes — a deterministic non-zero blockhash.
    private val blockhash07 = Base58.encode(ByteArray(32) { 0x07 })
    private val fixedBlockhash: () -> ByteArray = { ByteArray(32) }

    private fun splOffer(
        feePayer: String? = this.feePayer,
        memo: String? = null,
        recentBlockhash: String? = blockhash07,
    ) = X402AcceptsEntry(
        scheme = "exact",
        network = Network.SOLANA_DEVNET,
        asset = Mints.USDC_DEVNET,
        amount = "1000",
        payTo = payTo,
        extra = X402Extra(
            tokenProgram = Programs.TOKEN_PROGRAM,
            decimals = 6,
            feePayer = feePayer,
            memo = memo,
            recentBlockhash = recentBlockhash,
        ),
    )

    // ── Minimal v0 transaction decoder ────────────────────────────────────────

    private data class ParsedIx(val programIndex: Int, val accountIndices: IntArray, val data: ByteArray)
    private data class ParsedTx(
        val signatures: List<ByteArray>,
        val numRequiredSignatures: Int,
        val numReadonlySigned: Int,
        val numReadonlyUnsigned: Int,
        val accountKeys: List<ByteArray>,
        val blockhash: ByteArray,
        val instructions: List<ParsedIx>,
    )

    private class Cursor(val bytes: ByteArray) {
        var pos = 0
        fun u8(): Int = bytes[pos++].toInt() and 0xFF
        fun compactU16(): Int {
            var value = 0
            var shift = 0
            while (true) {
                val b = u8()
                value = value or ((b and 0x7F) shl shift)
                if (b and 0x80 == 0) break
                shift += 7
            }
            return value
        }
        fun take(n: Int): ByteArray = bytes.copyOfRange(pos, pos + n).also { pos += n }
    }

    private fun parseV0(raw: ByteArray): ParsedTx {
        val c = Cursor(raw)
        val sigCount = c.compactU16()
        val sigs = (0 until sigCount).map { c.take(64) }
        val versionByte = c.u8()
        require(versionByte == 0x80) { "expected v0 prefix 0x80, got $versionByte" }
        val numReq = c.u8()
        val numRoSigned = c.u8()
        val numRoUnsigned = c.u8()
        val keyCount = c.compactU16()
        val keys = (0 until keyCount).map { c.take(32) }
        val bh = c.take(32)
        val ixCount = c.compactU16()
        val ixs = (0 until ixCount).map {
            val programIndex = c.u8()
            val accCount = c.compactU16()
            val accIndices = IntArray(accCount) { c.u8() }
            val dataLen = c.compactU16()
            val data = c.take(dataLen)
            ParsedIx(programIndex, accIndices, data)
        }
        // Address table lookups tail (always 0 for this client).
        val atl = c.compactU16()
        require(atl == 0) { "expected no address table lookups, got $atl" }
        return ParsedTx(sigs, numReq, numRoSigned, numRoUnsigned, keys, bh, ixs)
    }

    private fun decode(encoded: String): ParsedTx =
        parseV0(Base64.getDecoder().decode(encoded))

    private fun keyB58(tx: ParsedTx, index: Int): String = Base58.encode(tx.accountKeys[index])

    // ── Instruction order ──────────────────────────────────────────────────────

    @Test
    fun instructionOrderIsLimitPriceTransferMemo() {
        val tx = decode(buildPayment(signer, splOffer(memo = "order_1"), fixedBlockhash).payload.transaction!!)
        assertEquals(4, tx.instructions.size, "limit, price, transferChecked, memo")

        // [0] SetComputeUnitLimit: ComputeBudget program, disc 2.
        assertEquals(Programs.COMPUTE_BUDGET_PROGRAM, keyB58(tx, tx.instructions[0].programIndex))
        assertEquals(2, tx.instructions[0].data[0].toInt())
        // [1] SetComputeUnitPrice: ComputeBudget program, disc 3.
        assertEquals(Programs.COMPUTE_BUDGET_PROGRAM, keyB58(tx, tx.instructions[1].programIndex))
        assertEquals(3, tx.instructions[1].data[0].toInt())
        // [2] transferChecked: token program, disc 12.
        assertEquals(Programs.TOKEN_PROGRAM, keyB58(tx, tx.instructions[2].programIndex))
        assertEquals(12, tx.instructions[2].data[0].toInt())
        // [3] memo: memo program.
        assertEquals(Programs.MEMO_PROGRAM, keyB58(tx, tx.instructions[3].programIndex))
        assertContentEquals("order_1".encodeToByteArray(), tx.instructions[3].data)
    }

    @Test
    fun nonceMemoAppendedWhenOfferHasNone() {
        // x402 SVM exact REQUIRES the client to always append exactly one Memo:
        // a nonce when the offer carries none. So a no-memo offer now produces
        // FOUR instructions (limit, price, transferChecked, nonce-memo), not
        // three. The trailing memo is the Memo program with the nonce data.
        val nonce = "0011223344556677"
        val tx = decode(
            buildPayment(signer, splOffer(memo = null), fixedBlockhash, nonceProvider = { nonce })
                .payload.transaction!!,
        )
        assertEquals(4, tx.instructions.size, "limit, price, transferChecked, nonce-memo")
        assertEquals(Programs.MEMO_PROGRAM, keyB58(tx, tx.instructions[3].programIndex))
        assertContentEquals(nonce.encodeToByteArray(), tx.instructions[3].data)
    }

    // ── transferChecked account indices ──────────────────────────────────────

    @Test
    fun transferCheckedAccountsAreSourceMintDestAuthority() {
        val offer = splOffer()
        val tx = decode(buildPayment(signer, offer, fixedBlockhash).payload.transaction!!)
        val transfer = tx.instructions[2]
        assertEquals(4, transfer.accountIndices.size, "transferChecked has 4 accounts")

        val mintKey = PublicKey.fromBase58(Mints.USDC_DEVNET)
        val tokenProgramKey = PublicKey.fromBase58(Programs.TOKEN_PROGRAM)
        val recipientKey = PublicKey.fromBase58(payTo)
        val expectedSource = Pda.associatedTokenAddress(signerKey, mintKey, tokenProgramKey).toBase58()
        val expectedDest = Pda.associatedTokenAddress(recipientKey, mintKey, tokenProgramKey).toBase58()

        // accounts = [source, mint, destination, authority]
        assertEquals(expectedSource, keyB58(tx, transfer.accountIndices[0]), "account[0] = source ATA")
        assertEquals(Mints.USDC_DEVNET, keyB58(tx, transfer.accountIndices[1]), "account[1] = mint")
        assertEquals(expectedDest, keyB58(tx, transfer.accountIndices[2]), "account[2] = destination ATA")
        assertEquals(signerKey.toBase58(), keyB58(tx, transfer.accountIndices[3]), "account[3] = authority")
    }

    @Test
    fun destinationIsAtaOfPayToMintTokenProgram() {
        val tx = decode(buildPayment(signer, splOffer(), fixedBlockhash).payload.transaction!!)
        val transfer = tx.instructions[2]
        val recipientKey = PublicKey.fromBase58(payTo)
        val mintKey = PublicKey.fromBase58(Mints.USDC_DEVNET)
        val tokenProgramKey = PublicKey.fromBase58(Programs.TOKEN_PROGRAM)
        val expectedDest = Pda.associatedTokenAddress(recipientKey, mintKey, tokenProgramKey).toBase58()
        assertEquals(expectedDest, keyB58(tx, transfer.accountIndices[2]))
    }

    // ── Signatures / fee payer ─────────────────────────────────────────────────

    @Test
    fun numRequiredSignaturesIsTwoWhenFeePayerPresent() {
        val tx = decode(buildPayment(signer, splOffer(feePayer = feePayer), fixedBlockhash).payload.transaction!!)
        assertEquals(2, tx.numRequiredSignatures, "fee payer + authority both sign")
        assertEquals(2, tx.signatures.size)
    }

    @Test
    fun feePayerSignatureSlotIsEmpty() {
        // Fee payer leads the account list (index 0); its signature slot must
        // be all-zero because the facilitator cosigns server-side.
        val tx = decode(buildPayment(signer, splOffer(feePayer = feePayer), fixedBlockhash).payload.transaction!!)
        assertEquals(feePayer, keyB58(tx, 0), "fee payer is the first account key")
        assertTrue(tx.signatures[0].all { it == 0.toByte() }, "fee payer slot must be empty")

        // The signer (authority) slot must be filled.
        val signerIdx = tx.accountKeys.indexOfFirst { it.contentEquals(signerKey.bytes) }
        assertTrue(signerIdx in 0 until tx.numRequiredSignatures, "signer must be a required signer")
        assertTrue(tx.signatures[signerIdx].any { it != 0.toByte() }, "signer slot must be filled")
    }

    @Test
    fun singleSignerWhenNoDistinctFeePayer() {
        // No feePayer => the signer is the fee payer, so only one signature.
        val tx = decode(buildPayment(signer, splOffer(feePayer = null), fixedBlockhash).payload.transaction!!)
        assertEquals(1, tx.numRequiredSignatures)
        assertEquals(signerKey.toBase58(), keyB58(tx, 0), "signer is the lone fee payer")
    }

    // ── Golden v0 SPL byte vector ───────────────────────────────────────────────

    @Test
    fun goldenV0SplVector() {
        // Deterministic inputs (seed 0x42*32, fee payer fixed, blockhash 0x07*32,
        // and a FIXED injected nonce memo) must always serialize to this exact
        // base64. The nonce source is injectable so this golden stays
        // deterministic despite the always-append-memo requirement. Regenerate
        // ONLY when the transaction shape intentionally changes, after
        // confirming the new bytes still pass the rust verifier.
        val offer = splOffer(feePayer = feePayer, memo = null, recentBlockhash = blockhash07)
        val encoded = buildPayment(
            signer,
            offer,
            fixedBlockhash,
            nonceProvider = { GOLDEN_NONCE },
        ).payload.transaction!!
        assertEquals(GOLDEN_V0_SPL, encoded)
    }

    companion object {
        // Fixed nonce for the golden vector (mirrors the rust spine's 16-byte
        // nonce hex-encoded to 32 chars; pinned here so the golden is stable).
        private const val GOLDEN_NONCE = "00112233445566778899aabbccddeeff"

        // Deterministic v0 SPL transferChecked transaction (seed 0x42*32, fee
        // payer 6Afz…, blockhash 0x07*32, fixed nonce memo GOLDEN_NONCE).
        // web3-solana builds the transferChecked; the paycore codec compiles
        // the v0 message.
        private const val GOLDEN_V0_SPL =
            "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                "AAAAAAAAAAAAAAAAAAC+9d4KvGvLnvf9Aa0wKa8eoMsZl71oOCtm6jxZ66sPn+BjAtX" +
                "pIZqYmMiDyd4xWT8Dp7raHnWmv04VTKGPYmELgAIABAhMxL7ko8h9WkSW5SwlG67XtS" +
                "JZiRPvwPGK09Jf9vRbhSFS+NGbeR0kRTJC4V8uq2y3z/p7al7TAJeWDgaYgdsSqLucG" +
                "/Qd4v5NMjQTvkWRrUlxle0D7MY2HMM6QMNHb6QF0v9ZVulbhkOsQH9ttW6uJjl0kF0Q" +
                "I+cdo95TKOHKWwMGRm/lIRcy/+ytunLDm+e8jOW7xfcSayxDmzpAAAAAO0Qss5EhV/E" +
                "6kz0BNCgtAytf/s0Botvxt3kGCN8ALqcG3fbh12Whk9nL4UbO63msHLSF7V9bN5E6jP" +
                "WFfv8AqQVKU1qZKSEGTSTocWDaOHx8NbXdvJK7geQfqEBBBUSNBwcHBwcHBwcHBwcHBw" +
                "cHBwcHBwcHBwcHBwcHBwcHBwcEBAAFAiBOAAAEAAkDAQAAAAAAAAAGBAIFAwEKDOgDAAA" +
                "AAAAABgcAIDAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYmNjZGRlZWZmAA=="
    }
}
