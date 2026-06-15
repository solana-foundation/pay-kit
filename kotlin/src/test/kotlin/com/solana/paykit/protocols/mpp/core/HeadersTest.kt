package com.solana.paykit.protocols.mpp.core

import com.solana.paykit.paycore.Base64Url
import com.solana.paykit.paycore.MppException

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
        val splits = decoded.methodDetails!!.splits
        assertNotNull(splits)
        assertEquals(2, splits.size)
        assertEquals("Vendor", splits[0].label)
        assertEquals("Tax", splits[1].label)
        assertEquals(true, splits[1].ataCreationRequired)
    }

    @Test
    fun rejectsOversizedRequestParam() {
        // Audit #9: the base64url `request` param is capped at MAX_TOKEN_LEN
        // before it is decoded + JSON-parsed, so a hostile server cannot force
        // proportionally large decode/parse work. One byte over the cap is
        // rejected at parse time.
        val oversized = "A".repeat(MppHeaders.MAX_TOKEN_LEN + 1)
        val header = "Payment id=\"abc\", realm=\"api\", method=\"solana\", " +
            "intent=\"charge\", request=\"$oversized\""
        assertFailsWith<MppException.InvalidHeader> {
            MppHeaders.parseWWWAuthenticate(header)
        }
    }

    @Test
    fun acceptsRequestParamAtMaxSize() {
        // Regression: a request param exactly at the cap must NOT trip the size
        // gate. We pad a valid charge-request JSON's base64url up to the cap
        // with trailing base64url chars; the size check runs before decode, so
        // reaching parseWWWAuthenticate without an InvalidHeader proves the
        // at-cap value passes the gate. (Decode/JSON validity is a separate
        // concern exercised elsewhere.)
        val base = validRequestB64()
        val padded = base + "A".repeat(MppHeaders.MAX_TOKEN_LEN - base.length)
        assertEquals(MppHeaders.MAX_TOKEN_LEN, padded.length)
        val header = "Payment id=\"abc\", realm=\"api\", method=\"solana\", " +
            "intent=\"charge\", request=\"$padded\""
        // The size gate must not fire. The padded base64 may or may not decode
        // to valid JSON, but it will NOT throw InvalidHeader from the size cap.
        try {
            MppHeaders.parseWWWAuthenticate(header)
        } catch (e: MppException.InvalidHeader) {
            throw AssertionError("at-cap request param must not trip the size gate", e)
        } catch (_: MppException) {
            // Any other MppException (e.g. base64/JSON) is acceptable here —
            // we are only asserting the size gate did not fire.
        }
    }

    @Test
    fun decodeChargeRequestRejectsOversizedRequest() {
        // The cap is also enforced in decodeChargeRequest for callers that
        // bypass parseWWWAuthenticate (e.g. a directly-constructed challenge).
        val oversized = "A".repeat(MppHeaders.MAX_TOKEN_LEN + 1)
        assertFailsWith<MppException.InvalidHeader> {
            MppHeaders.decodeChargeRequest(oversized)
        }
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
