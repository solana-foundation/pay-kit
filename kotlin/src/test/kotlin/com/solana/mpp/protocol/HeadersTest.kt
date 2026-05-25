package com.solana.mpp.protocol

import com.solana.mpp.crypto.*

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

/**
 * Targeted regression tests for MppHeaders covering the Rust spine
 * parity gaps surfaced by codex review of PR #105:
 *  - HTTP auth-param values may be either `token` or `quoted-string`
 *    (RFC 7235). The Rust reference parser accepts both; ours used to
 *    require quotes and rejected `method=solana`.
 *  - Duplicate auth-params must be rejected, matching the Rust ref.
 *    Silent overwrite would let a hostile header swap challenge-echo
 *    integrity fields (`id`, `request`, `digest`, `opaque`).
 *  - The comma-joined challenge splitter must treat HTAB as a
 *    challenge boundary too, not only ASCII space.
 */
class HeadersTest {
    private fun validRequestB64(): String {
        val json = """{"amount":"1","currency":"SOL","recipient":"r","methodDetails":{}}"""
        return Base64Url.encode(json.encodeToByteArray())
    }

    @Test
    fun parsesUnquotedTokenAuthParamValues() {
        val req = validRequestB64()
        val header = "Payment id=abc, realm=api, method=solana, intent=charge, request=\"$req\""
        val challenge = MppHeaders.parseWWWAuthenticate(header)
        assertEquals("abc", challenge.id)
        assertEquals("api", challenge.realm)
        assertEquals("solana", challenge.method)
        assertEquals("charge", challenge.intent)
    }

    @Test
    fun rejectsDuplicateAuthParams() {
        val req = validRequestB64()
        val header = "Payment id=\"abc\", id=\"def\", realm=\"api\", method=\"solana\", " +
            "intent=\"charge\", request=\"$req\""
        assertFailsWith<MppException.InvalidHeader> {
            MppHeaders.parseWWWAuthenticate(header)
        }
    }

    @Test
    fun acceptsLabeledSplitsAndUnknownFields() {
        // Server may emit splits with `label` (Rust SolanaChargeSplit) and
        // future-additive method-detail fields. The Kotlin decoder must
        // tolerate both rather than failing wire-compatibility before signing.
        val json = """{"amount":"100","currency":"USDC","recipient":"r",""" +
            """"methodDetails":{"network":"devnet","futureField":"x",""" +
            """"splits":[{"recipient":"r1","amount":"60","label":"Vendor"},""" +
            """{"recipient":"r2","amount":"40","label":"Tax","ataCreationRequired":true}]}}"""
        val req = Base64Url.encode(json.encodeToByteArray())
        val decoded = MppHeaders.decodeChargeRequest(req)
        val splits = decoded.methodDetails.splits
        assertNotNull(splits)
        assertEquals(2, splits.size)
        assertEquals("Vendor", splits[0].label)
        assertEquals("Tax", splits[1].label)
        assertEquals(true, splits[1].ataCreationRequired)
    }

    @Test
    fun splitsTabSeparatedChallenges() {
        val req = validRequestB64()
        // Two challenges joined by comma; second uses HTAB (\t) after
        // the scheme name. The splitter must still recognize the
        // boundary so the Solana charge challenge is selectable.
        val header = "Basic realm=\"x\", Payment\tid=\"abc\", realm=\"api\", " +
            "method=\"solana\", intent=\"charge\", request=\"$req\""
        val picked = MppHeaders.selectSolanaChargeChallenge(listOf(header))
        assertNotNull(picked)
        assertEquals("abc", picked.id)
    }
}
