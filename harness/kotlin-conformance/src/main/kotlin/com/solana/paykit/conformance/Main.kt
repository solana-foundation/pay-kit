package com.solana.paykit.conformance

import com.solana.paykit.paycore.PaymentChannels
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
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
 * Supports two canonical-bytes shapes:
 *  - input.voucherPreimage — drive PaymentChannels.voucherMessageBytes, the
 *    production SDK path the session signer uses. (session intent)
 *  - input.value — drive Rfc8785Json.encode on the typed JSON tree. The
 *    cyberphone/json-canonicalization testdata corpus (issue #110) lands
 *    here; the runner must implement the full RFC 8785 surface, not the
 *    integer-only subset the SDK's credential formatter uses.
 */

@Serializable
private data class VoucherPreimage(val channelId: String, val cumulativeAmount: String, val expiresAt: Long = 0)

@Serializable
private data class VectorInput(
    val voucherPreimage: VoucherPreimage? = null,
    val value: JsonElement? = null,
)

@Serializable
private data class Vector(val id: String, val intent: String? = null, val mode: String, val input: VectorInput)

@Serializable
private data class ExactBytes(
    val canonicalJson: String? = null,
    val base64Url: String? = null,
    val bytes: List<Int>? = null,
)

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

fun main() {
    val raw = System.`in`.readBytes().decodeToString()
    val result = try {
        runVector(json.decodeFromString(Vector.serializer(), raw))
    } catch (error: Throwable) {
        // Log to stderr with the runner's own UTF-8 writer so a malformed
        // vector with non-ASCII keys (cyberphone testdata/french, weird,
        // unicode) does not get mangled by the platform default charset.
        System.err.write("kotlin conformance runner error: ${error.message}\n".toByteArray(Charsets.UTF_8))
        RunnerResult(id = "unknown", outcome = "reject", error = error.message ?: "unknown error")
    }
    // The harness parses one JSON line from stdout. Write raw UTF-8
    // bytes — `println` uses the platform default charset which on
    // Windows is windows-1252 and mangles any non-ASCII codepoint
    // (the cyberphone corpus's `é`, `€`, `😂`, etc.) into U+FFFD or
    // a Latin-1 byte. The harness does not require a trailing newline
    // but most drivers expect one.
    val output = json.encodeToString(RunnerResult.serializer(), result) + "\n"
    System.out.write(output.toByteArray(Charsets.UTF_8))
    System.out.flush()
}

private fun runVector(vector: Vector): RunnerResult {
    if (vector.mode != "canonical-bytes") {
        return RunnerResult(
            vector.id, "reject",
            error = "unsupported-mode: kotlin conformance runner only implements canonical-bytes vectors",
        )
    }
    val preimage = vector.input.voucherPreimage
    if (preimage != null) {
        val cumulative = preimage.cumulativeAmount.toULongOrNull()
            ?: return RunnerResult(vector.id, "reject", error = "invalid cumulativeAmount ${preimage.cumulativeAmount}")
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
    val value = vector.input.value
    if (value != null && value !is JsonNull) {
        val canonical = Rfc8785Json.encode(value)
        val bytes = canonical.toByteArray(Charsets.UTF_8)
        return RunnerResult(
            id = vector.id,
            outcome = "accept",
            exactBytes = ExactBytes(
                canonicalJson = canonical,
                base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes),
            ),
        )
    }
    return RunnerResult(
        vector.id, "reject",
        error = "unsupported-mode: canonical-bytes vector has neither value nor voucherPreimage",
    )
}
