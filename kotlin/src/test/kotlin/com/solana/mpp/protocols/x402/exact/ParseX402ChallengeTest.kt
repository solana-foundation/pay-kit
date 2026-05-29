package com.solana.mpp.protocols.x402.exact

import com.solana.mpp._paycore.Mints
import com.solana.mpp._paycore.Network
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Unit tests for [parseX402Challenge] / [selectRequirement].
 *
 * Mirrors the Rust spine tests in
 * `rust/crates/x402/src/client/exact/payment.rs` (``select_*``) and the
 * Python precedent in ``python/src/pay_kit/protocols/x402/client/exact/payment.py``.
 */
class ParseX402ChallengeTest {

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Base64-encodes a JSON challenge envelope for the payment-required header. */
    private fun headerFor(json: String): String =
        Base64.getEncoder().encodeToString(json.toByteArray())

    private fun offer(
        network: String = Network.SOLANA_DEVNET,
        asset: String = "SOL",
        amount: String = "1000",
        payTo: String = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
        scheme: String = "exact",
        protocol: String? = "x402",
    ): String = buildString {
        append("""{"scheme":"$scheme","network":"$network","asset":"$asset","amount":"$amount","payTo":"$payTo"""")
        if (protocol != null) append(""","protocol":"$protocol"""")
        append("}")
    }

    private fun envelopeJson(vararg offers: String): String =
        """{"accepts":[${offers.joinToString(",")}]}"""

    // ── Basic parsing ─────────────────────────────────────────────────────────

    @Test
    fun parsesFromPaymentRequiredHeader() {
        val body = envelopeJson(offer())
        val headers = mapOf("payment-required" to headerFor(body))
        val result = parseX402Challenge(headers, null, ChallengeSelection())
        assertNotNull(result)
        assertEquals("SOL", result.asset)
    }

    @Test
    fun parsesFromHeaderCaseInsensitive() {
        val body = envelopeJson(offer())
        val headers = mapOf("Payment-Required" to headerFor(body))
        val result = parseX402Challenge(headers, null, ChallengeSelection())
        assertNotNull(result)
        assertEquals("SOL", result.asset)
    }

    @Test
    fun parsesFromBodyWhenNoHeader() {
        val body = envelopeJson(
            offer(asset = Mints.USDC_DEVNET, amount = "500"),
        )
        val result = parseX402Challenge(emptyMap(), body, ChallengeSelection())
        assertNotNull(result)
        assertEquals(Mints.USDC_DEVNET, result.asset)
    }

    @Test
    fun prefersHeaderOverBody() {
        val headerOffer = offer(amount = "100")
        val bodyOffer = offer(amount = "999")
        val headers = mapOf("payment-required" to headerFor(envelopeJson(headerOffer)))
        val result = parseX402Challenge(headers, envelopeJson(bodyOffer), ChallengeSelection())
        assertNotNull(result)
        assertEquals("100", result.amount)
    }

    @Test
    fun returnsNullForNoChallenge() {
        assertNull(parseX402Challenge(emptyMap(), null, ChallengeSelection()))
        assertNull(parseX402Challenge(emptyMap(), "{}", ChallengeSelection()))
        assertNull(parseX402Challenge(emptyMap(), "not-json", ChallengeSelection()))
    }

    @Test
    fun returnsNullWhenNoSolanaOfferPresent() {
        val body = """{"accepts":[{"scheme":"exact","network":"ethereum:1","asset":"ETH","amount":"1","payTo":"0x0"}]}"""
        assertNull(parseX402Challenge(emptyMap(), body, ChallengeSelection()))
    }

    @Test
    fun rejectsMalformedBase64Header() {
        val headers = mapOf("payment-required" to "!!!not_base64!!!")
        // Should fall through to body (which is null) → null.
        assertNull(parseX402Challenge(headers, null, ChallengeSelection()))
    }

    @Test
    fun acceptsOfferWithoutExplicitProtocolField() {
        // x402-express servers omit `protocol`; the spec treats absence as x402.
        val body = """{"accepts":[{"scheme":"exact","network":"${Network.SOLANA_DEVNET}","asset":"SOL","amount":"1","payTo":"ABC"}]}"""
        val result = parseX402Challenge(emptyMap(), body, ChallengeSelection())
        assertNotNull(result)
    }

    @Test
    fun rejectsOfferWithNonX402Protocol() {
        val body = """{"accepts":[{"scheme":"exact","network":"${Network.SOLANA_DEVNET}","protocol":"other","asset":"SOL","amount":"1","payTo":"ABC"}]}"""
        assertNull(parseX402Challenge(emptyMap(), body, ChallengeSelection()))
    }

    // ── Network selection ─────────────────────────────────────────────────────

    @Test
    fun defaultsToDevnetWhenNetworkIsNull() {
        // The harness default is devnet (EtWTRABZaYq6iMfeYKouRu166VU2xqa1).
        val devnetOffer = offer(network = Network.SOLANA_DEVNET, amount = "1")
        val mainnetOffer = offer(network = Network.SOLANA_MAINNET, amount = "999")
        val body = envelopeJson(mainnetOffer, devnetOffer)
        val result = parseX402Challenge(emptyMap(), body, ChallengeSelection(network = null))
        assertNotNull(result)
        assertEquals("1", result.amount, "should pick devnet offer (cheapest on preferred)")
    }

    @Test
    fun selectsMainnetWhenExplicitlyRequested() {
        val devnetOffer = offer(network = Network.SOLANA_DEVNET, amount = "1")
        val mainnetOffer = offer(network = Network.SOLANA_MAINNET, amount = "500")
        val body = envelopeJson(devnetOffer, mainnetOffer)
        val result = parseX402Challenge(emptyMap(), body, ChallengeSelection(network = "mainnet"))
        assertNotNull(result)
        assertEquals("500", result.amount, "should pick mainnet offer")
    }

    @Test
    fun resolvesCaip2NetworkStringDirectly() {
        val mainnetOffer = offer(network = Network.SOLANA_MAINNET, amount = "42")
        val body = envelopeJson(mainnetOffer)
        val result = parseX402Challenge(
            emptyMap(), body,
            ChallengeSelection(network = Network.SOLANA_MAINNET),
        )
        assertNotNull(result)
        assertEquals("42", result.amount)
    }

    @Test
    fun resolvesSlugAliases() {
        val devnet = mapOf(
            "devnet" to Network.SOLANA_DEVNET,
            "solana-devnet" to Network.SOLANA_DEVNET,
            "localnet" to Network.SOLANA_DEVNET,
        )
        for ((slug, caip2) in devnet) {
            val body = envelopeJson(offer(network = caip2))
            val result = parseX402Challenge(emptyMap(), body, ChallengeSelection(network = slug))
            assertNotNull(result, "slug=$slug should resolve to $caip2")
        }
    }

    @Test
    fun fallsBackToAnySolanaNetworkWhenPreferredHasNoOffers() {
        // Only mainnet offers available; client prefers devnet → falls back.
        val mainnetOffer = offer(network = Network.SOLANA_MAINNET, amount = "99")
        val body = envelopeJson(mainnetOffer)
        val result = parseX402Challenge(emptyMap(), body, ChallengeSelection(network = "devnet"))
        assertNotNull(result)
        assertEquals("99", result.amount, "should fall back to mainnet when devnet is unavailable")
    }

    // ── Currency selection ────────────────────────────────────────────────────

    @Test
    fun selectsFirstPreferredCurrencyInOrder() {
        // Server offers USDC then PYUSD; client prefers PYUSD first.
        val usdcOffer = offer(asset = Mints.USDC_DEVNET, amount = "1000000")
        val pyusdOffer = offer(asset = Mints.PYUSD_DEVNET, amount = "1000000")
        val body = envelopeJson(usdcOffer, pyusdOffer)
        val result = parseX402Challenge(
            emptyMap(), body,
            ChallengeSelection(currencies = listOf("PYUSD", "USDC")),
        )
        assertNotNull(result)
        assertEquals(Mints.PYUSD_DEVNET, result.asset, "should pick PYUSD as first preference")
    }

    @Test
    fun fallsBackToSecondChoiceWhenFirstUnavailable() {
        // Client wants USDT first, then USDC. Server doesn't offer USDT.
        val usdcOffer = offer(asset = Mints.USDC_DEVNET, amount = "1000")
        val body = envelopeJson(usdcOffer)
        val result = parseX402Challenge(
            emptyMap(), body,
            ChallengeSelection(currencies = listOf("USDT", "USDC")),
        )
        assertNotNull(result)
        assertEquals(Mints.USDC_DEVNET, result.asset)
    }

    @Test
    fun returnsNullWhenNoCurrencyMatchesClientList() {
        // Client only wants USDT; server offers USDC and SOL.
        val body = envelopeJson(
            offer(asset = Mints.USDC_DEVNET, amount = "1000"),
            offer(asset = "SOL", amount = "5000"),
        )
        val result = parseX402Challenge(
            emptyMap(), body,
            ChallengeSelection(currencies = listOf("USDT")),
        )
        assertNull(result)
    }

    @Test
    fun acceptsMintAddressAsPreferredCurrency() {
        val usdcOffer = offer(asset = Mints.USDC_DEVNET, amount = "777")
        val body = envelopeJson(usdcOffer)
        val result = parseX402Challenge(
            emptyMap(), body,
            ChallengeSelection(currencies = listOf(Mints.USDC_DEVNET)),
        )
        assertNotNull(result)
        assertEquals(Mints.USDC_DEVNET, result.asset)
    }

    @Test
    fun picksCheapestWhenNoCurrencyPreference() {
        // SOL costs 5000, stablecoins cost 1_000_000 → SOL wins.
        val usdcOffer = offer(asset = Mints.USDC_DEVNET, amount = "1000000")
        val solOffer = offer(asset = "SOL", amount = "5000")
        val body = envelopeJson(usdcOffer, solOffer)
        val result = parseX402Challenge(emptyMap(), body, ChallengeSelection(currencies = null))
        assertNotNull(result)
        assertEquals("SOL", result.asset)
        assertEquals("5000", result.amount)
    }

    @Test
    fun maxAmountRequiredFieldUsedWhenAmountIsAbsent() {
        val body = """{"accepts":[{"scheme":"exact","network":"${Network.SOLANA_DEVNET}","maxAmountRequired":"123","asset":"SOL","payTo":"A"}]}"""
        val result = parseX402Challenge(emptyMap(), body, ChallengeSelection())
        assertNotNull(result)
        assertEquals("123", result.maxAmountRequired)
    }
}
