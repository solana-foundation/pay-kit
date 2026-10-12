package com.solana.paykit.protocolrunner

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MainTest {
    private fun answer(line: String): JsonObject {
        val output = respond(line)
        assertFalse('\n' in output)
        return Json.parseToJsonElement(output).jsonObject
    }

    private fun JsonObject.field(name: String) = getValue(name).jsonPrimitive.content

    @Test
    fun parsesBasicChallengeWithRequestObject() {
        val request = """{"amount":"1000000","currency":"0x20c0000000000000000000000000000000000001","recipient":"0x1234567890abcdef1234567890abcdef12345678"}"""
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(request.encodeToByteArray())
        val line = buildJsonObject {
            put("op", "challenge.parse")
            putJsonObject("input") {
                put("header", """Payment id="ch_abc123", realm="api.example.com", method="tempo", intent="charge", request="$encoded"""")
            }
        }.toString()

        val response = answer(line)

        assertEquals("true", response.field("success"))
        assertEquals(
            Json.parseToJsonElement("""{"id":"ch_abc123","realm":"api.example.com","method":"tempo","intent":"charge","request":$request}"""),
            response["result"],
        )
    }

    @Test
    fun dropsEmptyOptionalField() {
        val header = """Payment id="ch", realm="r", method="tempo", intent="charge", request="e30", expires="""""
        val line = buildJsonObject {
            put("op", "challenge.parse")
            putJsonObject("input") { put("header", header) }
        }.toString()

        assertEquals(
            Json.parseToJsonElement("""{"id":"ch","realm":"r","method":"tempo","intent":"charge","request":{}}"""),
            answer(line)["result"],
        )
    }

    @Test
    fun emptyRequestIsAParseError() {
        val header = """Payment id="ch", realm="r", method="tempo", intent="charge", request="""""
        val line = buildJsonObject {
            put("op", "challenge.parse")
            putJsonObject("input") { put("header", header) }
        }.toString()

        val response = answer(line)

        assertEquals("false", response.field("success"))
        assertEquals("parse_error", response.field("error_type"))
    }

    @Test
    fun refusesNonJson() {
        assertEquals("runner_error", answer("not json").field("error_type"))
    }

    @Test
    fun unknownOpIsUnsupportedOperation() {
        assertEquals("unsupported_operation", answer("""{"op":"nope.op","input":{}}""").field("error_type"))
    }

    @Test
    fun sdkGapAnswersItsFamilyErrorType() {
        val response = answer("""{"op":"receipt.parse","input":{"header":"x"}}""")

        assertEquals("false", response.field("success"))
        assertEquals("parse_error", response.field("error_type"))
        assertTrue("unsupported" in response.field("error"))
    }

    @Test
    fun credentialPayloadHashIsAFormatError() {
        val credential = """{"challenge":{"id":"ch","realm":"r","method":"tempo","intent":"charge","request":{}},"payload":{"type":"hash","hash":"0x12"}}"""

        val response = answer("""{"op":"credential.format","input":$credential}""")

        assertEquals("format_error", response.field("error_type"))
        assertTrue("unknown key 'hash'" in response.field("error"))
    }
}
