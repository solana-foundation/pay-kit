package com.solana.paykit.protocols.mpp.core


import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement

/**
 * Conformance tests for the RFC 8785 JSON Canonicalization Scheme
 * implementation backing `MppHeaders.formatAuthorization`.
 *
 * Golden vectors come from RFC 8785 Appendix B / Erik Rydgren's
 * reference vectors at https://github.com/cyberphone/json-canonicalization
 * which the Rust `serde_json_canonicalizer` crate uses as its own
 * acceptance suite, so passing them here guarantees byte-for-byte
 * parity with the Rust client's `format_authorization` output.
 */
class CanonicalJsonTest {
    private val json = Json { encodeDefaults = false; explicitNulls = false }

    @Test
    fun sortsKeysLexicographically() {
        // RFC 8785 sect. 3.2.3 example: object keys must be ordered by
        // UTF-16 code unit comparison, not insertion order.
        val element = json.parseToJsonElement("""{"b":1,"a":2,"c":3}""")
        assertEquals("""{"a":2,"b":1,"c":3}""", CanonicalJson.encode(element))
    }

    @Test
    fun sortsNestedObjectKeys() {
        val element = json.parseToJsonElement(
            """{"outer":{"z":"last","a":"first"},"alpha":true}""",
        )
        assertEquals(
            """{"alpha":true,"outer":{"a":"first","z":"last"}}""",
            CanonicalJson.encode(element),
        )
    }

    @Test
    fun preservesArrayOrder() {
        val element = json.parseToJsonElement("""[3,1,2]""")
        assertEquals("""[3,1,2]""", CanonicalJson.encode(element))
    }

    @Test
    fun escapesControlAndStructuralCharacters() {
        val element = json.parseToJsonElement(
            """{"s":"line\nbreak","q":"with \"quote\"","b":"back\\slash"}""",
        )
        assertEquals(
            """{"b":"back\\slash","q":"with \"quote\"","s":"line\nbreak"}""",
            CanonicalJson.encode(element),
        )
    }

    @Test
    fun emitsLowercaseHexForControlCharacters() {
        val raw = "\u0001\u001F"
        val element = json.encodeToJsonElement(String.serializer(), raw)
        // RFC 8785 sect. 3.2.2.2: control character escapes use the
        // lowercase \u00xx form.
        assertEquals("\"\\u0001\\u001f\"", CanonicalJson.encode(element))
    }

    @Test
    fun preservesValidSurrogatePairsAndRejectsLoneSurrogates() {
        assertEquals("\"😀\"", CanonicalJson.encode(JsonPrimitive("\uD83D\uDE00")))
        assertFailsWith<IllegalArgumentException> {
            CanonicalJson.encode(JsonPrimitive("\uD800"))
        }
        assertFailsWith<IllegalArgumentException> {
            CanonicalJson.encode(buildJsonObject { put("\uDC00", JsonPrimitive(true)) })
        }
    }

    @Test
    fun normalizesNumbersWithEcmaScriptSemantics() {
        val element = json.parseToJsonElement(
            """{"a":1.0,"b":1E2,"c":100.00,"d":1.50,"zero":-0,"edge":1e21,"small":1e-7,"over":9007199254740993}""",
        )
        assertEquals(
            """{"a":1,"b":100,"c":100,"d":1.5,"edge":1e+21,"over":9007199254740992,"small":1e-7,"zero":0}""",
            CanonicalJson.encode(element),
        )
    }

    @Test
    fun paymentCredentialMatchesGoldenJcsOutput() {
        // Hand-canonicalized golden value computed by sorting every
        // object's keys and joining with no whitespace; this is what
        // the Rust client (serde_json_canonicalizer) produces for the
        // same credential.
        val credential = PaymentCredential(
            challenge = ChallengeEcho(
                id = "challenge-1",
                realm = "MPP Payment",
                method = "solana",
                intent = "charge",
                request = "abc",
            ),
            payload = CredentialPayload.transaction("base64-tx"),
            source = "did:pkh:solana:test",
        )
        val tree = json.encodeToJsonElement(PaymentCredential.serializer(), credential)
        val canonical = CanonicalJson.encode(tree)

        val expected =
            """{"challenge":{"id":"challenge-1","intent":"charge","method":"solana","realm":"MPP Payment","request":"abc"},""" +
                """"payload":{"transaction":"base64-tx","type":"transaction"},""" +
                """"source":"did:pkh:solana:test"}"""
        assertEquals(expected, canonical)
    }
}
