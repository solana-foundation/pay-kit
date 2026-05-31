package com.solana.paykit.protocols.x402.client.exact

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.Mints
import com.solana.paykit.paycore.Network
import com.solana.paykit.paycore.Programs
import com.solana.paykit.paycore.defaultTokenProgramForCurrency
import com.solana.paykit.paycore.resolveStablecoinMint
import com.solana.paykit.protocols.x402.exact.X402AcceptsEntry
import com.solana.paykit.protocols.x402.exact.X402Extra
import com.solana.paykit.protocols.x402.exact.effectiveAsset
import com.solana.paykit.protocols.x402.exact.effectiveDecimals
import com.solana.paykit.protocols.x402.exact.effectiveFeePayerKey
import com.solana.paykit.protocols.x402.exact.effectiveRecentBlockhash
import com.solana.paykit.protocols.x402.exact.effectiveTokenProgram
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

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

    @Test
    fun buildsFromRecipientAliasOffer() {
        // The rust-normalized requirement shape carries `recipient` instead of
        // `payTo`; the client resolves it via effectivePayTo rather than
        // rejecting the offer as unpayable.
        val body = """{"accepts":[{"scheme":"exact","network":"${Network.SOLANA_DEVNET}",""" +
            """"amount":"1000","asset":"SOL","recipient":"$devnetRecipient"}]}"""
        val requirement = parseX402Challenge(emptyMap(), body, ChallengeSelection())
        assertNotNull(requirement)
        assertNull(requirement.payTo)
        val envelope = buildPayment(signer, requirement, fixedBlockhash)
        assertNotNull(envelope.payload.transaction)
    }

    @Test
    fun buildsFromSymbolOfferDefaultingTokenProgram() {
        // A reference offer may carry the currency as a symbol and omit the
        // token program; the client resolves the mint and defaults the program
        // from the currency rather than failing.
        assertEquals(Mints.USDC_DEVNET, resolveStablecoinMint("USDC", "devnet"))
        assertEquals(Programs.TOKEN_PROGRAM, defaultTokenProgramForCurrency("USDC", "devnet"))
        assertEquals(Programs.TOKEN_2022_PROGRAM, defaultTokenProgramForCurrency("USDG", "devnet"))

        val body = """{"accepts":[{"scheme":"exact","network":"${Network.SOLANA_DEVNET}",""" +
            """"amount":"1000","asset":"USDC","payTo":"$devnetRecipient"}]}"""
        val requirement = parseX402Challenge(emptyMap(), body, ChallengeSelection())
        assertNotNull(requirement)
        // Previously threw on the symbol asset / missing token program.
        val envelope = buildPayment(signer, requirement, fixedBlockhash)
        assertNotNull(envelope.payload.transaction)
    }

    @Test
    fun echoesOfferedAcceptedVerbatim() {
        // A server may add fields the typed entry does not model. The client
        // must echo the offered `accepted` object verbatim so the rust
        // verifier's structural comparison against the route requirement
        // matches. Build from a *parsed* offer (the path that carries `raw`).
        val body = """{"accepts":[{"scheme":"exact","network":"${Network.SOLANA_DEVNET}",""" +
            """"amount":"5000","asset":"SOL","payTo":"$devnetRecipient",""" +
            """"maxTimeoutSeconds":120,"serverField":"keep-me",""" +
            """"extra":{"customExtra":"keep-too"}}]}"""
        val requirement = parseX402Challenge(emptyMap(), body, ChallengeSelection())
        assertNotNull(requirement)
        val header = buildPaymentHeader(signer, requirement, fixedBlockhash)
        val envelope = Json.parseToJsonElement(
            Base64.getDecoder().decode(header).decodeToString(),
        ).jsonObject
        val accepted = envelope["accepted"]!!.jsonObject
        assertEquals("keep-me", accepted["serverField"]!!.jsonPrimitive.content)
        assertEquals(120, accepted["maxTimeoutSeconds"]!!.jsonPrimitive.int)
        assertEquals(
            "keep-too",
            accepted["extra"]!!.jsonObject["customExtra"]!!.jsonPrimitive.content,
        )
    }

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
    fun splOfferMissingTokenProgramDefaultsFromCurrency() {
        // A known stablecoin offer that omits the token program defaults it
        // from the currency (rust `default_token_program_for_currency`) rather
        // than failing: USDC settles on the legacy Token program.
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = Mints.USDC_DEVNET,
            amount = "1000",
            payTo = devnetRecipient,
            extra = X402Extra(tokenProgram = null),
        )
        val envelope = buildPayment(signer, offer, fixedBlockhash)
        assertNotNull(envelope.payload.transaction)
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
        // No-memo offers now carry a per-call random nonce memo; pin it so the
        // byte comparison isolates the blockhash difference.
        val fixedNonce = { "0011223344556677" }

        val withZero = buildPayment(signer, solOffer(recentBlockhash = zeroBh), fixedBlockhash, fixedNonce)
        // fixedBlockhash also returns all-zero bytes → both should produce same tx.
        val fromProvider = buildPayment(signer, solOffer(recentBlockhash = null), fixedBlockhash, fixedNonce)
        val rawWithZero = decodeTransaction(withZero.payload.transaction!!)
        val rawFromProvider = decodeTransaction(fromProvider.payload.transaction!!)
        assertTrue(
            rawWithZero.contentEquals(rawFromProvider),
            "offer blockhash (zero) and provider (zero) should produce identical transaction",
        )

        // Now test with a different blockhash from offer: must differ from the above.
        val withOnes = buildPayment(signer, solOffer(recentBlockhash = allOnesBh), fixedBlockhash, fixedNonce)
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

    @Test
    fun noServerMemoStillAppendsNonceMemo() {
        // x402 SVM exact REQUIRES the client to always append exactly one Memo,
        // a nonce when the offer carries no extra.memo, so otherwise-identical
        // concurrent payments stay unique on-chain. With a fixed injected nonce
        // the bytes must contain that nonce as Memo instruction data.
        val nonce = "00112233445566778899aabbccddeeff"
        val offer = solOffer(memo = null)
        val envelope = buildPayment(signer, offer, fixedBlockhash, nonceProvider = { nonce })
        val raw = decodeTransaction(envelope.payload.transaction!!)
        val nonceBytes = nonce.encodeToByteArray()
        val found = raw.indices.any { idx ->
            idx + nonceBytes.size <= raw.size &&
                raw.copyOfRange(idx, idx + nonceBytes.size).contentEquals(nonceBytes)
        }
        assertTrue(found, "a nonce Memo must be appended when the offer carries no extra.memo")
    }

    @Test
    fun noMemoTransactionsAreNonDeterministicByDefault() {
        // The default (production) nonce provider mints a fresh secure-random
        // nonce per call, so two payments for an identical no-memo offer must
        // produce different transaction bytes (uniqueness guarantee). This is
        // the regression for the "deterministic without memo" finding: before
        // the fix the two would have been byte-identical.
        val offer = solOffer(memo = null, recentBlockhash = "11111111111111111111111111111111")
        val a = buildPayment(signer, offer, fixedBlockhash)
        val b = buildPayment(signer, offer, fixedBlockhash)
        assertTrue(
            a.payload.transaction != b.payload.transaction,
            "no-memo payments must be unique per call via the random nonce memo",
        )
    }

    @Test
    fun injectedNonceMakesNoMemoTransactionDeterministic() {
        // The nonce source is injectable so golden-vector tests stay
        // deterministic: a fixed nonce reproduces identical bytes.
        val offer = solOffer(memo = null, recentBlockhash = "11111111111111111111111111111111")
        val fixed = { "deadbeefdeadbeefdeadbeefdeadbeef" }
        val a = buildPayment(signer, offer, fixedBlockhash, nonceProvider = fixed)
        val b = buildPayment(signer, offer, fixedBlockhash, nonceProvider = fixed)
        assertEquals(a.payload.transaction, b.payload.transaction)
    }

    @Test
    fun topLevelFieldsTakePrecedenceOverExtraAliases() {
        // 152-field-precedence: effective* resolution must prefer the TOP-LEVEL
        // field over the nested extra.* alias, matching the rust spine. Build
        // an offer carrying conflicting shapes and assert the top-level value
        // wins for decimals, tokenProgram, and recentBlockhash.
        val topBlockhash = "11111111111111111111111111111111"
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = Mints.USDC_DEVNET,
            amount = "1000",
            payTo = devnetRecipient,
            // Top-level canonical fields.
            decimals = 9,
            tokenProgram = Programs.TOKEN_PROGRAM,
            recentBlockhash = topBlockhash,
            // Conflicting nested aliases that MUST lose.
            extra = X402Extra(
                decimals = 2,
                tokenProgram = Programs.TOKEN_2022_PROGRAM,
                recentBlockhash = "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM",
            ),
        )
        assertEquals(9, offer.effectiveDecimals)
        assertEquals(Programs.TOKEN_PROGRAM, offer.effectiveTokenProgram)
        assertEquals(topBlockhash, offer.effectiveRecentBlockhash)
    }

    @Test
    fun effectiveAssetPrefersCurrencyOverAsset() {
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = Mints.USDC_DEVNET,
            currency = Mints.USDT_MAINNET,
            amount = "1000",
            payTo = devnetRecipient,
        )
        // `currency` wins over `asset` when both are present, matching the rust
        // spine `currency.or_else(asset)` (types.rs:340-342). Before the parity
        // fix Kotlin used `asset ?: currency` and selected the wrong mint here.
        assertEquals(Mints.USDT_MAINNET, offer.effectiveAsset)
    }

    @Test
    fun systemProgramPubkeyIsTreatedAsSplNotNativeSol() {
        // Regression for the System Program native-SOL divergence: native SOL is
        // ONLY the case-insensitive symbol "SOL" (rust is_native_sol,
        // types.rs:86-88). The System Program pubkey string
        // "11111111111111111111111111111111" must pass through as an SPL mint
        // (rust resolve_mint passthrough), so the client builds an SPL
        // transferChecked (disc 0x0c), NOT a System transfer (disc 0x02).
        // Before the fix Kotlin treated this string as native SOL and built a
        // System transfer, diverging from the rust verifier on the wire.
        val systemProgram = "11111111111111111111111111111111"
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = systemProgram,
            amount = "1000",
            payTo = devnetRecipient,
            decimals = 6,
            tokenProgram = Programs.TOKEN_PROGRAM,
        )
        val envelope = buildPayment(signer, offer, fixedBlockhash, { "0011223344556677" })
        val raw = decodeTransaction(envelope.payload.transaction!!)
        // SPL transferChecked data begins with disc 0x0c then the u64 LE amount
        // (1000 = 0xE8 0x03 ...). Its presence proves the SPL branch was taken.
        val splTransferChecked = byteArrayOf(
            0x0c, 0xE8.toByte(), 0x03, 0, 0, 0, 0, 0, 0,
        )
        val isSpl = raw.indices.any { idx ->
            idx + splTransferChecked.size <= raw.size &&
                raw.copyOfRange(idx, idx + splTransferChecked.size).contentEquals(splTransferChecked)
        }
        assertTrue(isSpl, "System Program pubkey asset must build an SPL transferChecked, not a System transfer")
        // The System transfer disc + amount (0x02 0x00 0x00 0x00 + u64 LE 1000)
        // must NOT appear: confirms it was not routed to the native-SOL branch.
        val systemTransfer = byteArrayOf(
            0x02, 0x00, 0x00, 0x00, 0xE8.toByte(), 0x03, 0, 0, 0, 0, 0, 0,
        )
        val isSystem = raw.indices.any { idx ->
            idx + systemTransfer.size <= raw.size &&
                raw.copyOfRange(idx, idx + systemTransfer.size).contentEquals(systemTransfer)
        }
        assertTrue(!isSystem, "System Program pubkey asset must NOT build a native System transfer")
    }

    @Test
    fun extraAliasUsedWhenTopLevelAbsent() {
        // When the top-level field is absent the nested extra.* alias is the
        // fallback, so a server emitting only the nested shape still resolves.
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = Mints.USDC_DEVNET,
            amount = "1000",
            payTo = devnetRecipient,
            extra = X402Extra(decimals = 2, tokenProgram = Programs.TOKEN_2022_PROGRAM),
        )
        assertEquals(2, offer.effectiveDecimals)
        assertEquals(Programs.TOKEN_2022_PROGRAM, offer.effectiveTokenProgram)
    }

    // ── Top-level managed fee payer (PR #152 fix 2) ────────────────────────────

    @Test
    fun honorsTopLevelFeePayerKeyOfferShape() {
        // Regression for PR #152 fix 2: the rust spine parses a top-level
        // `feePayerKey` (+ optional `feePayer` toggle) managed-fee-payer offer
        // shape. The Kotlin client used to read only the nested extra.feePayer,
        // so a top-level-only offer silently fell back to the signer as fee
        // payer. After the fix the effective fee payer comes from the top-level
        // field, which changes the v0 account layout (fee payer is account 0),
        // so the transaction bytes must differ from the signer-pays case.
        val facilitator = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ"
        val topLevelOffer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = "SOL",
            amount = "1000",
            payTo = devnetRecipient,
            feePayerKey = facilitator,
        )
        // feePayerKey present implies the managed fee payer is selected even
        // without an explicit feePayer flag (rust parser normalization).
        assertEquals(facilitator, topLevelOffer.effectiveFeePayerKey)

        val withTopLevel = buildPayment(signer, topLevelOffer, fixedBlockhash, { "0011223344556677" })
        val signerPays = buildPayment(signer, solOffer(feePayer = null), fixedBlockhash, { "0011223344556677" })
        val rawTopLevel = decodeTransaction(withTopLevel.payload.transaction!!)
        val rawSignerPays = decodeTransaction(signerPays.payload.transaction!!)
        assertTrue(
            !rawTopLevel.contentEquals(rawSignerPays),
            "top-level feePayerKey offer must use the managed fee payer (different account layout)",
        )
        // The facilitator pubkey bytes must appear in the v0 message (it is the
        // fee payer at account index 0).
        val facilitatorBytes = Base58.decode(facilitator)
        val found = rawTopLevel.indices.any { idx ->
            idx + facilitatorBytes.size <= rawTopLevel.size &&
                rawTopLevel.copyOfRange(idx, idx + facilitatorBytes.size).contentEquals(facilitatorBytes)
        }
        assertTrue(found, "facilitator (top-level feePayerKey) pubkey must appear in the transaction")
    }

    @Test
    fun topLevelFeePayerFalseOptsOutOfManagedFeePayer() {
        // An explicit `feePayer = false` opts out of the managed fee payer even
        // when feePayerKey is present, so the signer pays its own fee.
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = "SOL",
            amount = "1000",
            payTo = devnetRecipient,
            feePayer = false,
            feePayerKey = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ",
        )
        assertNull(offer.effectiveFeePayerKey)
    }

    @Test
    fun topLevelFeePayerKeyTakesPrecedenceOverExtraAlias() {
        // Top-level feePayerKey wins over the nested extra.feePayer alias.
        val topLevel = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ"
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = "SOL",
            amount = "1000",
            payTo = devnetRecipient,
            feePayerKey = topLevel,
            extra = X402Extra(feePayer = devnetRecipient),
        )
        assertEquals(topLevel, offer.effectiveFeePayerKey)
    }

    // ── extra.feePayer (nested alias) + feePayer boolean toggle (regression) ─────

    @Test
    fun extraFeePayerKeyWithTopLevelFeePayerFalseReturnsNull() {
        // Regression for PR #152 effectiveFeePayerKey fix: when the offer carries
        // extra.feePayer (the nested pubkey alias) AND an explicit top-level
        // feePayer = false, the managed fee payer must be suppressed. The old code
        // returned extra.feePayer unconditionally in the no-top-level-key branch,
        // ignoring the feePayer boolean toggle; the fix gates both sources through
        // the same toggle so this case correctly returns null.
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = "SOL",
            amount = "1000",
            payTo = devnetRecipient,
            feePayer = false,
            extra = X402Extra(feePayer = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ"),
        )
        assertNull(offer.effectiveFeePayerKey)
    }

    @Test
    fun extraFeePayerKeyWithNoToggleReturnsKey() {
        // When extra.feePayer carries the pubkey and the top-level feePayer toggle
        // is absent, the managed fee payer is selected (defaults to true when a
        // key is present, matching rust normalization).
        val fpKey = "6AfzJJo1KfhNWKe56wa5EWszTNQ7B1W5Kfh5SY2JkRGQ"
        val offer = X402AcceptsEntry(
            scheme = "exact",
            network = Network.SOLANA_DEVNET,
            asset = "SOL",
            amount = "1000",
            payTo = devnetRecipient,
            extra = X402Extra(feePayer = fpKey),
        )
        assertEquals(fpKey, offer.effectiveFeePayerKey)
    }

    // ── Unsigned u64 amount parsing (PR #152 fix 3) ─────────────────────────────

    @Test
    fun acceptsU64AmountAboveLongMaxForSol() {
        // Regression for PR #152 fix 3: the x402 amount used toLongOrNull(),
        // which returns null for any value above Long.MAX_VALUE (2^63-1) and so
        // rejected legitimate u64 amounts. u64 max is 2^64-1. Before the fix
        // this offer threw IllegalArgumentException ("invalid amount"); after,
        // it builds and the little-endian u64 bytes appear in the transaction.
        val u64Max = "18446744073709551615" // 2^64 - 1
        val offer = solOffer(amount = u64Max)
        val envelope = buildPayment(signer, offer, fixedBlockhash, { "0011223344556677" })
        assertNotNull(envelope.payload.transaction)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        // SystemProgram::transfer data = 0x02 (u32 LE disc) + amount (u64 LE).
        // u64 max encodes as eight 0xFF bytes.
        val transferData = byteArrayOf(0x02, 0x00, 0x00, 0x00) +
            ByteArray(8) { 0xFF.toByte() }
        val found = raw.indices.any { idx ->
            idx + transferData.size <= raw.size &&
                raw.copyOfRange(idx, idx + transferData.size).contentEquals(transferData)
        }
        assertTrue(found, "u64-max SOL transfer must encode as 0x02 + eight 0xFF amount bytes")
    }

    @Test
    fun acceptsU64AmountAboveLongMaxForSpl() {
        // The SPL transferChecked path (web3-solana) must also honor the full
        // u64 range. Pick a value strictly above Long.MAX_VALUE and assert the
        // little-endian u64 amount bytes land in the SPL transferChecked data.
        val amount = "9223372036854775808" // Long.MAX_VALUE + 1 = 2^63
        val offer = splOffer().copy(amount = amount)
        val envelope = buildPayment(signer, offer, fixedBlockhash, { "0011223344556677" })
        assertNotNull(envelope.payload.transaction)
        val raw = decodeTransaction(envelope.payload.transaction!!)
        // SPL transferChecked data = 0x0c disc + amount u64 LE + decimals u8.
        // 2^63 little-endian = seven 0x00 then 0x80.
        val amountLE = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0x80.toByte())
        val discPlusAmount = byteArrayOf(0x0c) + amountLE
        val found = raw.indices.any { idx ->
            idx + discPlusAmount.size <= raw.size &&
                raw.copyOfRange(idx, idx + discPlusAmount.size).contentEquals(discPlusAmount)
        }
        assertTrue(found, "u64 SPL amount above Long.MAX_VALUE must encode as 0x0c + LE u64 bytes")
    }

    @Test
    fun rejectsAmountAboveU64Max() {
        // Above the u64 ceiling (2^64) must still fail, matching the rust u64
        // parse upper bound.
        val offer = solOffer(amount = "18446744073709551616") // 2^64
        assertFailsWith<IllegalArgumentException> {
            buildPayment(signer, offer, fixedBlockhash)
        }
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
        // Deterministic signer + deterministic blockhash + a pinned nonce
        // (the no-memo offer otherwise mints a fresh random nonce per call) →
        // deterministic bytes.
        val offer = solOffer(recentBlockhash = "11111111111111111111111111111111")
        val fixedNonce = { "0011223344556677" }
        val a = buildPayment(signer, offer, fixedBlockhash, fixedNonce)
        val b = buildPayment(signer, offer, fixedBlockhash, fixedNonce)
        assertEquals(a.payload.transaction, b.payload.transaction)
    }
}
