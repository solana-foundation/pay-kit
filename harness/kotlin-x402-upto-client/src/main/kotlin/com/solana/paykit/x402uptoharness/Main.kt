package com.solana.paykit.x402uptoharness

import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.protocols.x402.client.upto.buildUptoHeader
import com.solana.paykit.protocols.x402.client.upto.parseUptoChallenge

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.util.concurrent.TimeUnit

/**
 * Cross-language harness adapter for the Kotlin x402 ``upto`` client.
 *
 * Mirrors the Rust/Go/Python upto harness clients: GET the target, parse the
 * ``upto`` 402 challenge, build the ``Payment-Signature`` header (a partially
 * signed channel ``open`` plus the upto payload), GET again with it, then print
 * exactly one result JSON line to stdout. All diagnostics go to stderr.
 *
 * Env contract (shared with the rust/go/python upto clients):
 *
 * - ``X402_HARNESS_TARGET_URL``         required, the gated resource URL.
 * - ``X402_HARNESS_CLIENT_SECRET_KEY``  required, JSON int array (signer bytes).
 * - ``X402_HARNESS_NETWORK``            optional, CAIP-2 / slug (informational).
 */
fun main() {
    try {
        runAdapter()
    } catch (error: Throwable) {
        System.err.println("kotlin-x402-upto harness adapter error: ${error.message}")
        error.printStackTrace(System.err)
        val failure = buildJsonObject {
            put("type", "result")
            put("implementation", "kotlin")
            put("role", "client")
            put("ok", false)
            put("status", 0)
            put("responseHeaders", buildJsonObject {})
            put("responseBody", JsonPrimitive(error.message ?: "unknown error"))
            put("settlement", JsonPrimitive(null as String?))
        }
        println(Json.encodeToString(JsonObject.serializer(), failure))
        kotlin.system.exitProcess(1)
    }
}

private const val SETTLEMENT_HEADER = "x-payment-settlement-signature"
private const val PAYMENT_SIGNATURE_HEADER = "Payment-Signature"
private const val DEFAULT_MAX_TIMEOUT_SECONDS = 300L

private fun runAdapter() {
    val targetUrl = requireEnv("X402_HARNESS_TARGET_URL")
    val secretKey = parseSecretKey(requireEnv("X402_HARNESS_CLIENT_SECRET_KEY"))
    val signer = MemorySigner.fromSecretKey(secretKey)

    val okHttp = OkHttpClient.Builder()
        .connectTimeout(60, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .callTimeout(150, TimeUnit.SECONDS)
        .build()

    val first = okHttp.newCall(Request.Builder().url(targetUrl).get().build()).execute()
    val firstHeaders = headerMap(first)
    val firstBody = first.use { it.body?.string() ?: "" }

    val requirement = parseUptoChallenge(firstHeaders, firstBody)
    if (requirement == null) {
        emit(
            ok = false,
            status = first.code,
            headers = firstHeaders,
            body = firstBody,
            settlement = null,
            error = "server did not return a supported x402 upto challenge",
        )
        return
    }

    val expiresAt = System.currentTimeMillis() / 1000L +
        (requirement.maxTimeoutSeconds.takeIf { it > 0 } ?: DEFAULT_MAX_TIMEOUT_SECONDS)
    val paymentHeader = buildUptoHeader(signer, requirement, expiresAt)

    val paid = okHttp.newCall(
        Request.Builder().url(targetUrl).header(PAYMENT_SIGNATURE_HEADER, paymentHeader).get().build(),
    ).execute()
    val paidHeaders = headerMap(paid)
    val paidBody = paid.use { it.body?.string() ?: "" }

    emit(
        ok = paid.code in 200..299,
        status = paid.code,
        headers = paidHeaders,
        body = paidBody,
        settlement = paidHeaders[SETTLEMENT_HEADER],
        error = null,
    )
}

private fun headerMap(response: Response): Map<String, String> = buildMap {
    for (name in response.headers.names()) {
        put(name.lowercase(), response.headers.values(name).joinToString(", "))
    }
}

private fun emit(
    ok: Boolean,
    status: Int,
    headers: Map<String, String>,
    body: String,
    settlement: String?,
    error: String?,
) {
    val parsedBody = try {
        Json.parseToJsonElement(body)
    } catch (_: Throwable) {
        JsonPrimitive(body)
    }
    val result = buildJsonObject {
        put("type", "result")
        put("implementation", "kotlin")
        put("role", "client")
        put("ok", ok)
        put("status", status)
        put(
            "responseHeaders",
            buildJsonObject { for ((k, v) in headers) put(k, v) },
        )
        put("responseBody", parsedBody)
        if (settlement != null) put("settlement", settlement) else put("settlement", JsonPrimitive(null as String?))
        if (error != null) put("error", error)
    }
    println(Json.encodeToString(JsonObject.serializer(), result))
}

private fun requireEnv(name: String): String =
    System.getenv(name)?.takeIf { it.isNotBlank() } ?: error("$name is required")

/** Parses the JSON-array-of-bytes form Solana keypair files use. */
internal fun parseSecretKey(raw: String): ByteArray {
    val element = Json.parseToJsonElement(raw)
    if (element !is JsonArray) {
        error("X402_HARNESS_CLIENT_SECRET_KEY must be a JSON array of bytes")
    }
    val bytes = ByteArray(element.size)
    for ((index, value) in element.withIndex()) {
        val long = value.jsonPrimitive.longOrNull
            ?: error("non-integer byte at index $index in secret key")
        if (long < 0L || long > 255L) {
            throw IllegalArgumentException("byte at index $index out of range 0..255: $long")
        }
        bytes[index] = long.toInt().toByte()
    }
    if (bytes.size != 32 && bytes.size != 64) {
        error("X402_HARNESS_CLIENT_SECRET_KEY must be 32 or 64 bytes (got ${bytes.size})")
    }
    return bytes
}
