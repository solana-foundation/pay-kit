// Kotlin mpp-protocol conformance runner.
// Reads one adapter-ABI request on stdin and writes one response line on stdout,
// per the contract in harness/src/protocol/runners/spawn.ts.
package com.solana.paykit.protocolrunner

import com.solana.paykit.protocols.mpp.core.MppHeaders
import com.solana.paykit.protocols.mpp.core.PaymentChallenge
import com.solana.paykit.protocols.mpp.core.PaymentCredential
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.util.Base64
import kotlin.system.exitProcess

private val families = mapOf(
    "challenge.parse" to "parse_error",
    "credential.parse" to "parse_error",
    "receipt.parse" to "parse_error",
    "challenge.format" to "format_error",
    "credential.format" to "format_error",
    "receipt.format" to "format_error",
    "base64url.encode" to "encoding_error",
    "base64url.decode" to "encoding_error",
    "challenge.id" to "generation_error",
)

private val sdkGaps = families.keys - setOf("challenge.parse", "credential.format")

fun main() {
    val response = reply(System.`in`.readBytes().decodeToString())
    println(response)
    if (response["error_type"] == JsonPrimitive("runner_error")) exitProcess(1)
}

internal fun respond(line: String): String = reply(line).toString()

private fun reply(line: String): JsonObject {
    val (op, input) = try {
        val request = Json.parseToJsonElement(line).jsonObject
        request["op"]?.jsonPrimitive?.content.orEmpty() to (request["input"] ?: JsonNull)
    } catch (error: IllegalArgumentException) {
        return fail(error.message, "runner_error")
    }
    val family = families[op] ?: return fail("unknown operation: $op", "unsupported_operation")
    if (op in sdkGaps) return fail("$op unsupported by the Kotlin SDK", family)
    return try {
        val result = if (op == "challenge.parse") parseChallenge(input) else formatCredential(input)
        buildJsonObject {
            put("success", true)
            put("result", result)
        }
    } catch (error: Exception) {
        fail(error.message, family)
    }
}

private fun fail(error: String?, errorType: String) = buildJsonObject {
    put("success", false)
    put("error", error)
    put("error_type", errorType)
}

private fun parseChallenge(input: JsonElement): JsonObject {
    val challenge = MppHeaders.parseWWWAuthenticate(input.jsonObject.getValue("header").jsonPrimitive.content)
    val fields = Json.encodeToJsonElement(PaymentChallenge.serializer(), challenge).jsonObject
    return JsonObject(
        fields.filter { (name, value) -> name !in setOf("expires", "digest") || value != JsonPrimitive("") }.mapValues { (name, value) ->
            if (name == "request" || name == "opaque") decodeJson(value.jsonPrimitive.content) else value
        },
    )
}

private fun decodeJson(base64Url: String): JsonElement =
    Json.parseToJsonElement(Base64.getUrlDecoder().decode(base64Url).decodeToString())

private fun formatCredential(input: JsonElement): JsonObject {
    val credential = input.jsonObject
    val challenge = credential.getValue("challenge").jsonObject
    val request = (challenge["request"] ?: JsonObject(emptyMap())).toString().encodeToByteArray()
    val echo = challenge + ("request" to JsonPrimitive(Base64.getUrlEncoder().withoutPadding().encodeToString(request)))
    val wire = JsonObject(credential + ("challenge" to JsonObject(echo)))
    return buildJsonObject {
        put("header", MppHeaders.formatAuthorization(Json.decodeFromJsonElement(PaymentCredential.serializer(), wire)))
    }
}
