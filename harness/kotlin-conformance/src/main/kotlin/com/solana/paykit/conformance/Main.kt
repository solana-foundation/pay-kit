package com.solana.paykit.conformance

import com.solana.paykit.paycore.PaymentChannels
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Cross-SDK conformance-vector runner for the Kotlin SDK.
 *
 * Honors the same stdin/stdout contract as the TypeScript reference runner
 * (harness/src/conformance/ts-runner.ts), the Go runner (go/cmd/conformance),
 * and the Swift runner (swift Sources/mpp-conformance): read one conformance
 * vector as JSON on stdin, drive the real SDK path for the requested
 * intent + mode, and emit one RunnerResult line as JSON on stdout. Anything
 * else (JVM/BouncyCastle chatter) must go to stderr so the harness parses a
 * single clean JSON line.
 *
 * The Kotlin SDK is client-only. Canonical-byte vectors drive its real MPP
 * CanonicalJson encoder, while session voucher vectors use
 * PaymentChannels.voucherMessageBytes.
 */

@Serializable
private data class VoucherPreimage(val channelId: String, val cumulativeAmount: String, val expiresAt: Long)

@Serializable
private data class VectorInput(val voucherPreimage: VoucherPreimage? = null)

@Serializable
private data class Vector(val id: String, val intent: String? = null, val mode: String, val input: VectorInput)

@Serializable
private data class ExactBytes(
    val canonicalJson: String? = null,
    val bytes: List<Int>? = null,
    val base64Url: String? = null,
)

@Serializable
private data class RunnerResult(
    val language: String = "kotlin",
    val implementation: String = "kotlin",
    val id: String,
    val outcome: String,
    val exactBytes: ExactBytes? = null,
    val error: String? = null,
)

private val json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
    explicitNulls = false
}

private val vectorIdPattern = Regex("\\\"id\\\"\\s*:\\s*\\\"([A-Za-z0-9._-]+)\\\"")

fun main() {
    val raw = System.`in`.readBytes().decodeToString()
    println(renderVectorResult(raw))
}

internal fun renderVectorResult(raw: String): String {
    val result = try {
        val vector = json.decodeFromString(Vector.serializer(), raw)
        val input = json.parseToJsonElement(raw).jsonObject["input"]?.jsonObject
            ?: error("conformance vector missing input object")
        runVector(vector, input)
    } catch (error: Throwable) {
        System.err.println("kotlin conformance runner error: ${error.message}")
        val id = vectorIdPattern.find(raw)?.groupValues?.get(1) ?: "unknown"
        RunnerResult(id = id, outcome = "reject", error = error.message ?: "unknown error")
    }
    return json.encodeToString(RunnerResult.serializer(), result)
}

private fun runVector(vector: Vector, rawInput: Map<String, JsonElement>): RunnerResult {
    if (vector.mode != "canonical-bytes") {
        return RunnerResult(
            id = vector.id, outcome = "reject",
            error = "unsupported-mode: kotlin conformance runner only implements canonical-bytes vectors",
        )
    }

    rawInput["value"]?.let { value ->
        val canonical = CanonicalJsonBridge.encode(value)
        return RunnerResult(
            id = vector.id,
            outcome = "accept",
            exactBytes = ExactBytes(
                canonicalJson = canonical,
                base64Url = base64Url(canonical.encodeToByteArray()),
            ),
        )
    }

    rawInput["encodeBase64Url"]?.jsonObject?.let { value ->
        value["hexBytes"]?.jsonPrimitive?.content?.let { hex ->
            val bytes = hexToBytes(hex)
            return RunnerResult(
                id = vector.id,
                outcome = "accept",
                exactBytes = ExactBytes(bytes = bytes.map { it.toInt() and 0xff }, base64Url = base64Url(bytes)),
            )
        }
        value["utf8"]?.jsonPrimitive?.content?.let { text ->
            return RunnerResult(
                id = vector.id,
                outcome = "accept",
                exactBytes = ExactBytes(base64Url = base64Url(text.encodeToByteArray())),
            )
        }
        error("encodeBase64Url needs hexBytes or utf8")
    }

    rawInput["challengeId"]?.jsonObject?.let { challenge ->
        fun field(name: String): String = challenge[name]?.jsonPrimitive?.content
            ?: error("challengeId missing $name")
        val material = listOf(
            field("realm"), field("method"), field("intent"), field("request"),
            challenge["expires"]?.jsonPrimitive?.content.orEmpty(),
            challenge["digest"]?.jsonPrimitive?.content.orEmpty(),
            challenge["opaque"]?.jsonPrimitive?.content.orEmpty(),
        ).joinToString("|")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(field("secretKey").encodeToByteArray(), "HmacSHA256"))
        return RunnerResult(
            id = vector.id,
            outcome = "accept",
            exactBytes = ExactBytes(base64Url = base64Url(mac.doFinal(material.encodeToByteArray()))),
        )
    }

    val preimage = vector.input.voucherPreimage
        ?: return RunnerResult(
            id = vector.id, outcome = "reject",
            error = "kotlin conformance runner needs input.value, base64url, challengeId, or a session voucherPreimage",
        )
    val cumulative = preimage.cumulativeAmount.toULongOrNull()
        ?: return RunnerResult(id = vector.id, outcome = "reject", error = "invalid cumulativeAmount ${preimage.cumulativeAmount}")

    // Drive the real SDK encoder so the byte assertion exercises the same path
    // the session voucher signer uses.
    val bytes = PaymentChannels.voucherMessageBytes(preimage.channelId, cumulative, preimage.expiresAt)
    return RunnerResult(
        id = vector.id,
        outcome = "accept",
        exactBytes = ExactBytes(
            bytes = bytes.map { it.toInt() and 0xff },
            base64Url = base64Url(bytes),
        ),
    )
}

private fun base64Url(bytes: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

private fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hexBytes must have an even length" }
    return ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}
