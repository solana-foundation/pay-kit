package com.solana.paykit.x402interop

import com.solana.paykit.client.PayKitClient
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.protocols.x402.client.exact.ChallengeSelection
import com.solana.paykit.protocols.x402.client.exact.X402RpcClient

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

/**
 * Cross-language harness adapter for the Kotlin x402 ``exact`` client.
 *
 * Mirrors the Rust spine interop client at
 * ``rust/crates/x402/src/bin/interop_client.rs``: GET the target, parse the
 * x402 challenge with the client's network + currency-preference selection,
 * build the ``Payment-Signature`` header, GET again with it, then print
 * exactly one result JSON line to stdout. All diagnostics go to stderr.
 *
 * Env contract (shared with the rust/python/ts clients):
 *
 * - ``X402_INTEROP_TARGET_URL``         required, the gated resource URL.
 * - ``X402_INTEROP_RPC_URL``            required, Solana RPC (blockhash fallback).
 * - ``X402_INTEROP_NETWORK``            CAIP-2 / slug; default devnet CAIP-2.
 * - ``X402_INTEROP_CLIENT_SECRET_KEY``  required, JSON int array.
 * - ``X402_INTEROP_PREFER_CURRENCIES``  optional, comma-separated preference list.
 */
fun main() {
    try {
        runAdapter()
    } catch (error: Throwable) {
        System.err.println("kotlin-x402 interop adapter error: ${error.message}")
        error.printStackTrace(System.err)
        val failure = buildJsonObject {
            put("type", "result")
            put("implementation", "kotlin-x402")
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

private const val DEFAULT_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
private const val SETTLEMENT_HEADER = "x-fixture-settlement"

private fun runAdapter() {
    val targetUrl = requireEnv("X402_INTEROP_TARGET_URL")
    val rpcUrl = requireEnv("X402_INTEROP_RPC_URL")
    val network = System.getenv("X402_INTEROP_NETWORK")?.takeIf { it.isNotBlank() } ?: DEFAULT_NETWORK
    val secretKey = parseSecretKey(requireEnv("X402_INTEROP_CLIENT_SECRET_KEY"))

    val preferRaw = System.getenv("X402_INTEROP_PREFER_CURRENCIES")
    val currencies: List<String>? = if (!preferRaw.isNullOrBlank()) {
        preferRaw.split(",").map { it.trim() }.filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }
    } else null

    val signer = MemorySigner.fromSecretKey(secretKey)
    val okHttp = OkHttpClient.Builder()
        .connectTimeout(60, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .callTimeout(150, TimeUnit.SECONDS)
        .build()

    val rpcClient = X402RpcClient(rpcUrl, okHttp)
    val selection = ChallengeSelection(network = network, currencies = currencies)
    val client = PayKitClient.Builder()
        .signer(signer)
        .okHttpClient(okHttp)
        .x402(
            rpcBlockhashProvider = { rpcClient.fetchRecentBlockhash() },
            selection = selection,
        )
        .build()

    val getResult = runBlocking { client.get(targetUrl) }
    val response = getResult.response
    try {
        val status = response.code
        val responseHeaders = response.headers
        val headerMap = buildJsonObject {
            for (name in responseHeaders.names()) {
                val lower = name.lowercase()
                val joined = responseHeaders.values(name).joinToString(", ")
                put(lower, joined)
            }
            // Inject "payment-signature-sent" so the harness can confirm the
            // payment flow happened (mirrors the Python adapter convention).
            if (getResult.paymentHeader != null) {
                put("payment-signature-sent", getResult.paymentHeader)
            }
        }
        val rawBody = response.body?.string() ?: ""
        val parsedBody = try {
            Json.parseToJsonElement(rawBody)
        } catch (_: Throwable) {
            JsonPrimitive(rawBody)
        }
        val settlementHeaderName =
            (System.getenv("X402_INTEROP_SETTLEMENT_HEADER")?.takeIf { it.isNotBlank() }
                ?: SETTLEMENT_HEADER).lowercase()
        val settlement = headerMap[settlementHeaderName]?.jsonPrimitive?.content

        val result = buildJsonObject {
            put("type", "result")
            put("implementation", "kotlin-x402")
            put("role", "client")
            put("ok", status in 200..299)
            put("status", status)
            put("responseHeaders", headerMap)
            put("responseBody", parsedBody)
            if (settlement != null) {
                put("settlement", settlement)
            } else {
                put("settlement", JsonPrimitive(null as String?))
            }
        }
        println(Json.encodeToString(JsonObject.serializer(), result))
    } finally {
        response.close()
    }
}

private fun requireEnv(name: String): String =
    System.getenv(name) ?: error("$name is required")

/**
 * Parses the JSON-array-of-bytes form Solana keypair files use.
 * Identical to the MPP interop adapter's parseSecretKey.
 */
internal fun parseSecretKey(raw: String): ByteArray {
    val element = Json.parseToJsonElement(raw)
    if (element !is JsonArray) {
        error("X402_INTEROP_CLIENT_SECRET_KEY must be a JSON array of bytes")
    }
    val bytes = ByteArray(element.size)
    for ((index, value) in element.withIndex()) {
        val long = value.jsonPrimitive.longOrNull
            ?: error("non-integer byte at index $index in secret key")
        if (long < 0L || long > 255L) {
            throw IllegalArgumentException(
                "byte at index $index out of range 0..255: $long",
            )
        }
        bytes[index] = long.toInt().toByte()
    }
    if (bytes.size != 32 && bytes.size != 64) {
        error("X402_INTEROP_CLIENT_SECRET_KEY must be 32 or 64 bytes (got ${bytes.size})")
    }
    return bytes
}
