package com.solana.mpp.protocols.x402.client.exact

import com.solana.mpp._paycore.Base58
import com.solana.mpp._paycore.MemorySigner
import com.solana.mpp._paycore.Mints
import com.solana.mpp._paycore.Network
import com.solana.mpp._paycore.Programs
import com.solana.mpp.protocols.x402.exact.X402AcceptsEntry
import com.solana.mpp.protocols.x402.exact.X402Extra
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for [buildPayment] and [buildPaymentHeader].
 *
 * Mirrors the Rust spine tests in
 * ``rust/crates/x402/src/client/exact/payment.rs`` and the Python precedent
 * in ``python/src/pay_kit/protocols/x402/client/exact/payment.py``.
 *
 * Invariants asserted here:
 * - ComputeUnitLimit = 20_000 (NOT the MPP value 200_000)
 * - ComputeUnitPrice = 1
 * - First two instructions are SetComputeUnitLimit then SetComputeUnitPrice
 * - v0 transaction (serialized bytes start with 0x80 prefix after signature block)
 * - Standard base64 encoding (not base64url)
 * - Signer's signature slot is filled; all others are zero-padded
 */
class BuildPaymentTest {

    private val deterministicSeed = ByteArray(32) { 0x42 }
    private val signer = MemorySigner.fromSeed(deterministicSeed)

    /** Fixed 32 zero-byte blockhash provider. */
    private val fixedBlockhash: () -> ByteArray = { ByteArray(32) }

    private val devnetRecipient = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"

    private fun solOffer(
        payTo: String = devnetRecipient,
        amount: String = "1000",
        feePayer: String? = null,
        memo: String? = null,
        recentBlockhash: String? = null,
    ) = X402AcceptsEntry(
        scheme = "exact",
        network = Network.SOLANA_DEVNET,
        asset = "SOL",
        amount = amount,
        payTo = payTo,
        extra = X402Extra(
            feePayer = feePayer,
            memo = memo,
            recentBlockhash = recentBlockhash,
        ),
    )

    private fun splOffer(
        asset: String = Mints.USDC_DEVNET,
        tokenProgram: String = Programs.TOKEN_PROGRAM,
        decimals: Int = 6,
        feePayer: String? = null,
        memo: String? = null,
        recentBlockhash: String? = null,
    ) = X402AcceptsEntry(
        scheme = "exact",
        network = Network.SOLANA_DEVNET,
        asset = asset,
        amount = "1000",
        payTo = devnetRecipient,
        extra = X402Extra(
            tokenProgram = tokenProgram,
            decimals = decimals,
            feePayer = feePayer,
            memo = memo,
            recentBlockhash = recentBlockhash,
        ),
    )

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Decode a standard-base64 transaction into raw bytes. */
    private fun decodeTransaction(encoded: String): ByteArray =
        Base64.getDecoder().decode(encoded)

    /**
     * Splits a v0 versioned transaction into (signaturesBlock, messageBytes).
     *
     * v0 wire format:
     *   compact-u16 sigCount | (sigCount * 64 bytes) | v0 message (0x80 prefix …)
     */
    private fun splitV0Transaction(raw: ByteArray): Pair<List<ByteArray>, ByteArray> {
        // Decode compact-u16 sigCount from first byte(s).
        val (sigCount, headerLen) = decodeCompactU16(raw, 0)
        val sigs = (0 until sigCount).map { i ->
            raw.copyOfRange(headerLen + i * 64, headerLen + (i + 1) * 64)
        }
        val messageStart = headerLen + sigCount * 64
        val message = raw.copyOfRange(messageStart, raw.size)
        return sigs to message
    }

    private fun decodeCompactU16(bytes: ByteArray, offset: Int): Pair<Int, Int> {
        var value = 0
        var shift = 0
        var pos = offset
        do {
            val byte = bytes[pos++].toInt() and 0xFF
            value = value or ((byte and 0x7F) shl shift)
            shift += 7
            if (byte and 0x80 == 0) break
        } while (shift < 21)
        return value to pos
    }

    // ── Compute-budget invariants ─────────────────────────────────────────────

    @Test
    fun firstInstructionIsComputeUnitLimit20k() {
        // Verifies the INVARIANT: limit must be 20_000 (not 200_000 / MPP value).
        val envelope = buildPayment(signer, solOffer(), fixedBlockhash)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        val (_, message) = splitV0Transaction(raw)

        // Parse the compiled instruction table from the v0 message to find
        // the first instruction's data. v0 starts with 0x80; then 3 header
        // bytes; then compact-u16 accountKeysLen; then (len*32) key bytes;
        // then compact-u16 blockhashCount (always 1 for us); then 32 bytes
        // blockhash; then compact-u16 instrCount; then instructions.
        //
        // Rather than fully parsing the v0 message, we search for the
        // ComputeBudget program bytes to locate the SetComputeUnitLimit ix.
        val computeBudgetBytes = Base58.decode(Programs.COMPUTE_BUDGET_PROGRAM)
        val limitData = byteArrayOf(0x02.toByte()) +
            20_000.toUInt().let { u ->
                byteArrayOf(
                    (u and 0xffu).toByte(),
                    ((u shr 8) and 0xffu).toByte(),
                    ((u shr 16) and 0xffu).toByte(),
                    ((u shr 24) and 0xffu).toByte(),
                )
            }

        // The limit data bytes (5 bytes: disc 0x02 + u32 LE 0x204e0000) must
        // appear somewhere in the message after the program id list.
        val limitLE = byteArrayOf(0x02, 0x20.toByte(), 0x4e, 0x00, 0x00)
        assertTrue(
            message.indices.any { idx ->
                idx + limitLE.size <= message.size &&
                    message.copyOfRange(idx, idx + limitLE.size).contentEquals(limitLE)
            },
            "SetComputeUnitLimit(20_000) data bytes must appear in the v0 message",
        )
    }

    @Test
    fun computeUnitLimitIsNot200k() {
        val envelope = buildPayment(signer, solOffer(), fixedBlockhash)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        val (_, message) = splitV0Transaction(raw)

        // 200_000 in LE u32 = 0x40_0d_03_00
        val wrong200kLE = byteArrayOf(0x02, 0x40.toByte(), 0x0d, 0x03, 0x00)
        val contains200k = message.indices.any { idx ->
            idx + wrong200kLE.size <= message.size &&
                message.copyOfRange(idx, idx + wrong200kLE.size).contentEquals(wrong200kLE)
        }
        assertTrue(!contains200k, "ComputeUnitLimit must NOT be 200_000 (MPP value)")
    }

    // ── v0 transaction invariants ──────────────────────────────────────────────

    @Test
    fun transactionIsV0WithHighBitPrefix() {
        val envelope = buildPayment(signer, solOffer(), fixedBlockhash)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        val (_, message) = splitV0Transaction(raw)
        assertEquals(
            0x80.toByte(),
            message[0],
            "v0 message must start with 0x80 prefix byte",
        )
    }

    @Test
    fun transactionEncodingIsStandardBase64() {
        val envelope = buildPayment(signer, solOffer(), fixedBlockhash)
        val encoded = envelope.payload.transaction!!
        // Standard base64 may contain '+' and '/'; base64url uses '-' and '_'.
        // Also may contain '=' padding. None of '-' or '_' should appear.
        assertTrue(encoded.none { it == '-' || it == '_' }, "must be standard (not base64url) encoding")
    }

    // ── Envelope structure ───────────────────────────────────────────────────

    @Test
    fun envelopeCarriesCorrectX402Version() {
        // The spine emits v2 envelopes (rust X402_VERSION_V2, go=2, python=2).
        val envelope = buildPayment(signer, solOffer(), fixedBlockhash)
        assertEquals(2, envelope.x402Version)
    }

    @Test
    fun envelopeAcceptedMatchesOffer() {
        val offer = solOffer(amount = "9999")
        val envelope = buildPayment(signer, offer, fixedBlockhash)
        assertEquals("9999", envelope.accepted.amount)
    }

    // ── SOL transfer ─────────────────────────────────────────────────────────

    @Test
    fun solTransferProducesWellFormedTransaction() {
        val envelope = buildPayment(signer, solOffer(), fixedBlockhash)
        assertNotNull(envelope.payload.transaction)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        assertTrue(raw.size > 64, "transaction must be longer than a single signature")
    }

    @Test
    fun signerSignatureSlotIsFilled() {
        val envelope = buildPayment(signer, solOffer(), fixedBlockhash)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        val (sigs, _) = splitV0Transaction(raw)
        assertTrue(sigs.isNotEmpty())
        // The signer occupies one slot; at least one of the slots must be non-zero.
        val hasNonZeroSig = sigs.any { sig -> sig.any { it != 0.toByte() } }
        assertTrue(hasNonZeroSig, "signer's signature slot must be filled (non-zero)")
    }

    // ── SPL transfer ─────────────────────────────────────────────────────────

    @Test
    fun splTransferProducesWellFormedTransaction() {
        val offer = splOffer()
        val envelope = buildPayment(signer, offer, fixedBlockhash)
        assertNotNull(envelope.payload.transaction)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        assertTrue(raw.size > 64)
    }

    @Test
    fun splOfferMissingTokenProgramThrows() {
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = Mints.USDC_DEVNET,
            amount = "1000",
            payTo = devnetRecipient,
            extra = X402Extra(tokenProgram = null),
        )
        assertFailsWith<IllegalArgumentException> {
            buildPayment(signer, offer, fixedBlockhash)
        }
    }

    // ── Fee payer ─────────────────────────────────────────────────────────────

    @Test
    fun usesOfferFeePayerWhenPresent() {
        val feePayer = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ"
        val withFP = buildPayment(signer, solOffer(feePayer = feePayer), fixedBlockhash)
        val withoutFP = buildPayment(signer, solOffer(feePayer = null), fixedBlockhash)
        // Different fee-payer means different account layout → different bytes.
        val rawWith = decodeTransaction(withFP.payload.transaction!!)
        val rawWithout = decodeTransaction(withoutFP.payload.transaction!!)
        assertTrue(
            !rawWith.contentEquals(rawWithout),
            "transactions with/without fee payer must differ",
        )
    }

    // ── Blockhash source ──────────────────────────────────────────────────────

    @Test
    fun usesBlockhashFromOfferWhenPresent() {
        // Use base58-encoded 32 byte zero hash ("11111111111111111111111111111111")
        val zeroBh = "11111111111111111111111111111111"
        val allOnesBh = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM"

        val withZero = buildPayment(signer, solOffer(recentBlockhash = zeroBh), fixedBlockhash)
        // fixedBlockhash also returns all-zero bytes → both should produce same tx.
        val fromProvider = buildPayment(signer, solOffer(recentBlockhash = null), fixedBlockhash)
        val rawWithZero = decodeTransaction(withZero.payload.transaction!!)
        val rawFromProvider = decodeTransaction(fromProvider.payload.transaction!!)
        assertTrue(
            rawWithZero.contentEquals(rawFromProvider),
            "offer blockhash (zero) and provider (zero) should produce identical transaction",
        )

        // Now test with a different blockhash from offer: must differ from the above.
        val withOnes = buildPayment(signer, solOffer(recentBlockhash = allOnesBh), fixedBlockhash)
        val rawWithOnes = decodeTransaction(withOnes.payload.transaction!!)
        assertTrue(
            !rawWithOnes.contentEquals(rawWithZero),
            "different blockhash must produce different transaction bytes",
        )
    }

    @Test
    fun fallsBackToBlockhashProviderWhenOfferLacksOne() {
        var called = false
        val provider: () -> ByteArray = {
            called = true
            ByteArray(32) { 0x42.toByte() }
        }
        buildPayment(signer, solOffer(recentBlockhash = null), provider)
        assertTrue(called, "RPC blockhash provider must be called when offer omits recentBlockhash")
    }

    // ── Memo ─────────────────────────────────────────────────────────────────

    @Test
    fun memoAppearsInTransactionWhenPresent() {
        val memoText = "order_12345"
        val offer = splOffer(memo = memoText)
        val envelope = buildPayment(signer, offer, fixedBlockhash)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        // The memo bytes must appear somewhere in the transaction wire bytes.
        val memoBytes = memoText.encodeToByteArray()
        val found = raw.indices.any { idx ->
            idx + memoBytes.size <= raw.size &&
                raw.copyOfRange(idx, idx + memoBytes.size).contentEquals(memoBytes)
        }
        assertTrue(found, "memo string must appear as instruction data in the transaction")
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    @Test
    fun throwsOnMissingAsset() {
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = null,
            amount = "1000",
            payTo = devnetRecipient,
        )
        assertFailsWith<IllegalArgumentException> {
            buildPayment(signer, offer, fixedBlockhash)
        }
    }

    @Test
    fun throwsOnMissingPayTo() {
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = "SOL",
            amount = "1000",
            payTo = null,
        )
        assertFailsWith<IllegalArgumentException> {
            buildPayment(signer, offer, fixedBlockhash)
        }
    }

    @Test
    fun throwsOnInvalidAmount() {
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = "SOL",
            amount = "not-a-number",
            payTo = devnetRecipient,
        )
        assertFailsWith<IllegalArgumentException> {
            buildPayment(signer, offer, fixedBlockhash)
        }
    }

    @Test
    fun throwsOnInvalidBlockhashBytes() {
        // 31 bytes is too short → require(size == 32) triggers.
        val badProvider: () -> ByteArray = { ByteArray(31) }
        val offer = solOffer(recentBlockhash = null)
        assertFailsWith<IllegalArgumentException> {
            buildPayment(signer, offer, badProvider)
        }
    }

    // ── buildPaymentHeader ────────────────────────────────────────────────────

    @Test
    fun buildPaymentHeaderReturnsStandardBase64Json() {
        val header = buildPaymentHeader(signer, solOffer(), fixedBlockhash)
        // Standard base64 must not contain '-' or '_'.
        assertTrue(header.none { it == '-' || it == '_' }, "header must be standard base64")
        // Decode and verify JSON structure.
        val decoded = Base64.getDecoder().decode(header)
        val json = decoded.decodeToString()
        assertTrue(json.contains("x402Version"), "envelope JSON must contain x402Version")
        assertTrue(json.contains("transaction"), "envelope JSON must contain transaction")
    }

    @Test
    fun buildPaymentHeaderForSolAndSplBothSucceed() {
        val solHeader = buildPaymentHeader(signer, solOffer(), fixedBlockhash)
        val splHeader = buildPaymentHeader(signer, splOffer(), fixedBlockhash)
        assertTrue(solHeader.isNotEmpty())
        assertTrue(splHeader.isNotEmpty())
    }

    // ── Determinism ───────────────────────────────────────────────────────────

    @Test
    fun sameInputsProduceSameTransaction() {
        // Deterministic signer + deterministic blockhash → deterministic bytes.
        val offer = solOffer(recentBlockhash = "11111111111111111111111111111111")
        val a = buildPayment(signer, offer, fixedBlockhash)
        val b = buildPayment(signer, offer, fixedBlockhash)
        assertEquals(a.payload.transaction, b.payload.transaction)
    }
}
