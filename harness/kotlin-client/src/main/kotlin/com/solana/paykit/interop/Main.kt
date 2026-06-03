package com.solana.paykit.interop

import com.solana.paykit.client.PayKitClient
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.protocols.mpp.client.JsonRpcClient
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
 * Interop adapter for the MPP Kotlin client.
 *
 * Reads the env-var contract documented at
 * harness/README.md and skills/pay-sdk-implementation/references/interop-harness.md,
 * pays the target URL, and emits exactly one `result` JSON line on
 * stdout. Anything else (BouncyCastle init chatter, OkHttp HTTP2
 * complaints, JVM warnings) must go to stderr so the harness parses a
 * single clean JSON line.
 */
fun main() {
    // Force any unexpected logs to stderr by default; the standard
    // System.err is already off the message channel.
    try {
        runAdapter()
    } catch (error: Throwable) {
        System.err.println("kotlin interop adapter error: ${error.message}")
        error.printStackTrace(System.err)
        // Emit a structured failure result so the harness fails the
        // scenario cleanly instead of timing out on missing stdout.
        val failure = buildJsonObject {
            put("type", "result")
            put("implementation", "kotlin")
            put("role", "client")
            put("ok", false)
            put("status", 0)
            put("responseHeaders", buildJsonObject {})
            put("responseBody", JsonPrimitive(error.message ?: "unknown error"))
        }
        println(Json.encodeToString(JsonObject.serializer(), failure))
        kotlin.system.exitProcess(1)
    }
}

private fun runAdapter() {
    val targetUrl = requireEnv("MPP_INTEROP_TARGET_URL")
    val rpcUrl = requireEnv("MPP_INTEROP_RPC_URL")
    val secretKey = parseSecretKey(requireEnv("MPP_INTEROP_CLIENT_SECRET_KEY"))
    val settlementHeader = System.getenv("MPP_INTEROP_SETTLEMENT_HEADER")
        ?: "x-fixture-settlement"

    val signer = MemorySigner.fromSecretKey(secretKey)
    // Surfpool-backed RPCs and proxied charge servers can take >10s to
    // respond on the first warm-up, well beyond OkHttp's default 10s read
    // timeout. The interop harness already enforces a 180s per-scenario
    // ceiling, so generous client-side timeouts surface real server hangs
    // without flagging warm-up latency as a failure.
    val okHttp = OkHttpClient.Builder()
        .connectTimeout(60, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .callTimeout(150, TimeUnit.SECONDS)
        .build()
    val rpc = JsonRpcClient(rpcUrl, okHttp)
    val client = PayKitClient.Builder()
        .signer(signer)
        .okHttpClient(okHttp)
        .charge(blockhashProvider = rpc)
        .build()

    val response = runBlocking { client.get(targetUrl) }.response
    try {
        val status = response.code
        val responseHeaders = response.headers
        val headerObject = buildJsonObject {
            for (name in responseHeaders.names()) {
                val lower = name.lowercase()
                // Headers with multiple values are joined with ', ' per RFC 7230.
                val joined = responseHeaders.values(name).joinToString(", ")
                put(lower, joined)
            }
        }
        val rawBody = response.body?.string() ?: ""
        val parsedBody = try {
            Json.parseToJsonElement(rawBody)
        } catch (_: Throwable) {
            JsonPrimitive(rawBody)
        }
        val settlement = headerObject[settlementHeader.lowercase()]?.jsonPrimitive?.content

        val result = buildJsonObject {
            put("type", "result")
            put("implementation", "kotlin")
            put("role", "client")
            put("ok", status in 200..299)
            put("status", status)
            put("responseHeaders", headerObject)
            put("responseBody", parsedBody)
            if (settlement != null) {
                put("settlement", settlement)
            } else {
                put("settlement", JsonPrimitive(null as String?))
            }
        }
        // The single result message; stdout discipline.
        println(Json.encodeToString(JsonObject.serializer(), result))
    } finally {
        response.close()
    }
}

private fun requireEnv(name: String): String =
    System.getenv(name) ?: error("$name is required")

/**
 * Parses the JSON-array-of-bytes form Solana keypair files use and the
 * MPP interop harness ships in MPP_INTEROP_CLIENT_SECRET_KEY.
 */
internal fun parseSecretKey(raw: String): ByteArray {
    val element = Json.parseToJsonElement(raw)
    if (element !is JsonArray) {
        error("MPP_INTEROP_CLIENT_SECRET_KEY must be a JSON array of bytes")
    }
    val bytes = ByteArray(element.size)
    for ((index, value) in element.withIndex()) {
        // Read as Long first so values outside Int range surface as
        // out-of-range rather than wrapping. `longOrNull?.toInt()`
        // would coerce e.g. 4294967296 to 0 silently, bypassing the
        // 0..255 guard and producing a different signer.
        val long = value.jsonPrimitive.longOrNull
            ?: error("non-integer byte at index $index in secret key")
        // Guard the 0..255 range explicitly so out-of-range values do
        // not silently wrap through Int.toByte() (e.g. 256 becoming 0,
        // -1 becoming 255), which would produce a different signer
        // without any error surfacing to the caller.
        if (long < 0L || long > 255L) {
            throw IllegalArgumentException(
                "byte at index $index out of range 0..255: $long",
            )
        }
        bytes[index] = long.toInt().toByte()
    }
    // Sanity check the size before handing off to MemorySigner.
    if (bytes.size != 32 && bytes.size != 64) {
        error("MPP_INTEROP_CLIENT_SECRET_KEY must be 32 or 64 bytes (got ${bytes.size})")
    }
    return bytes
}
