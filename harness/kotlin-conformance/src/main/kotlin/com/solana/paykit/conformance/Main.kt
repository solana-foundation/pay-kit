package com.solana.paykit.conformance

import com.solana.paykit.paycore.PaymentChannels
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.util.Base64

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
 * The Kotlin SDK is CLIENT-only and the harness drives it for the `session`
 * intent only (harness/runners/kotlin.json). The single session vector shipped
 * today is the canonical-bytes 50-byte voucher preimage; this runner decodes
 * input.voucherPreimage and emits the bytes via the real
 * PaymentChannels.voucherMessageBytes encoder. Any other mode is reported as an
 * unsupported-mode reject the driver skips.
 */

@Serializable
private data class VoucherPreimage(val channelId: String, val cumulativeAmount: String, val expiresAt: Long = 0)

@Serializable
private data class VectorInput(val voucherPreimage: VoucherPreimage? = null)

@Serializable
private data class Vector(val id: String, val intent: String? = null, val mode: String, val input: VectorInput)

@Serializable
private data class ExactBytes(val bytes: List<Int>? = null, val base64Url: String? = null)

@Serializable
private data class RunnerResult(
    val id: String,
    val outcome: String,
    val exactBytes: ExactBytes? = null,
    val error: String? = null,
)

private val json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = false
    explicitNulls = false
}

/** Intents this runner implements; pkc checks them against harness/expectations/kotlin.toml. */
private val CLAIMED_INTENTS = listOf("session")

private fun resultFor(raw: String): RunnerResult = try {
    runVector(json.decodeFromString(Vector.serializer(), raw))
} catch (error: Throwable) {
    System.err.println("kotlin conformance runner error: ${error.message}")
    RunnerResult(id = "unknown", outcome = "reject", error = error.message ?: "unknown error")
}

/**
 * Testee ABI v2 (harness/README.md): newline JSON `{id, op, input}` in,
 * `{id, ok, result | error}` out, one long-lived process. `input` is the v1
 * vector and `result` the v1 RunnerResult.
 */
private fun serve() {
    while (true) {
        val line = readlnOrNull() ?: break
        if (line.isBlank()) continue
        val request: JsonObject? = try {
            json.parseToJsonElement(line).jsonObject
        } catch (error: Throwable) {
            null
        }
        val response: JsonElement = if (request == null) {
            buildJsonObject {
                put("id", JsonNull)
                put("ok", false)
                put("error", "bad-request")
                put("detail", "request is not a JSON object")
            }
        } else {
            val id = request["id"] ?: JsonNull
            when ((request["op"] as? JsonPrimitive)?.content) {
                "capabilities" -> buildJsonObject {
                    put("id", id)
                    put("ok", true)
                    put("result", buildJsonObject {
                        put("abi", 2)
                        put("language", "kotlin")
                        put("intents", buildJsonArray { CLAIMED_INTENTS.forEach { add(JsonPrimitive(it)) } })
                        put("honoursClock", false)
                    })
                }
                "build", "verify", "canonical-bytes" -> {
                    val input = request["input"]?.toString() ?: "{}"
                    buildJsonObject {
                        put("id", id)
                        put("ok", true)
                        put("result", json.encodeToJsonElement(RunnerResult.serializer(), resultFor(input)))
                    }
                }
                else -> buildJsonObject {
                    put("id", id)
                    put("ok", false)
                    put("error", "unknown-op")
                    put("detail", request["op"]?.toString() ?: "null")
                }
            }
        }
        println(response.toString())
        System.out.flush()
    }
}

fun main(args: Array<String>) {
    if (args.contains("--serve")) {
        serve()
        return
    }
    val raw = System.`in`.readBytes().decodeToString()
    println(json.encodeToString(RunnerResult.serializer(), resultFor(raw)))
}

private fun runVector(vector: Vector): RunnerResult {
    if (vector.mode != "canonical-bytes") {
        return RunnerResult(
            vector.id, "reject",
            error = "unsupported-mode: kotlin conformance runner only implements canonical-bytes session vectors",
        )
    }
    val preimage = vector.input.voucherPreimage
        ?: return RunnerResult(
            vector.id, "reject",
            error = "unsupported-mode: kotlin conformance runner only supports the session voucherPreimage canonical-bytes vector",
        )
    val cumulative = preimage.cumulativeAmount.toULongOrNull()
        ?: return RunnerResult(vector.id, "reject", error = "invalid cumulativeAmount ${preimage.cumulativeAmount}")

    // Drive the real SDK encoder so the byte assertion exercises the same path
    // the session voucher signer uses.
    val bytes = PaymentChannels.voucherMessageBytes(preimage.channelId, cumulative, preimage.expiresAt)
    return RunnerResult(
        id = vector.id,
        outcome = "accept",
        exactBytes = ExactBytes(
            bytes = bytes.map { it.toInt() and 0xff },
            base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
        ),
    )
}
