package com.solana.mpp.protocols.x402.exact

import com.solana.mpp._paycore.*

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/**
 * Result of an x402-aware GET, carrying the response and the header that was sent.
 *
 * The harness contract requires `Payment-Signature-sent` in the result's
 * responseHeaders so the harness can confirm the payment flow happened.
 */
data class X402GetResult(
    val response: Response,
    /** The raw ``Payment-Signature`` header value sent in the payment retry, or ``null`` when
     * no payment was needed (server returned non-402 initially). */
    val paymentSignatureSent: String?,
)

/**
 * x402-aware HTTP client built on OkHttp.
 *
 * On a 402 Payment Required response the client:
 *
 * 1. Parses the ``payment-required`` header (standard-base64 JSON) or body.
 * 2. Selects an x402 ``exact`` offer matching the client's network and currency
 *    preferences using [parseX402Challenge].
 * 3. Builds and signs the v0 payment transaction through [buildPaymentHeader].
 * 4. Replays the original request with a ``Payment-Signature`` header and
 *    returns the response.
 *
 * The retry is single-shot. The client deliberately does not retry on
 * 5xx, network errors, or other 4xx statuses: the x402 flow only applies
 * to 402.
 */
class X402HttpClient(
    private val signer: SolanaSigner,
    private val rpcBlockhashProvider: () -> ByteArray,
    private val selection: ChallengeSelection = ChallengeSelection(),
    private val okHttp: OkHttpClient = OkHttpClient(),
) {
    /**
     * Performs an x402-aware GET. Returns an [X402GetResult] containing the
     * final response and the ``Payment-Signature`` that was sent (or ``null``
     * when no payment was required). Callers are responsible for closing the
     * response body via [X402GetResult.response].
     */
    fun get(url: String, extraHeaders: Map<String, String> = emptyMap()): X402GetResult {
        val initial = execute("GET", url, extraHeaders, body = null)
        if (initial.code != 402) {
            return X402GetResult(response = initial, paymentSignatureSent = null)
        }

        // Collect all response headers (lowercased) and body before closing.
        val responseHeaders = mutableMapOf<String, String>()
        val responseBody: String
        initial.use { resp ->
            for (name in resp.headers.names()) {
                // Join multi-values with ", " per RFC 7230.
                responseHeaders[name.lowercase()] = resp.headers.values(name).joinToString(", ")
            }
            responseBody = resp.body?.string() ?: ""
        }

        val requirement = parseX402Challenge(responseHeaders, responseBody, selection)
            ?: throw IllegalStateException("x402: server did not return a supported SVM x402 challenge")

        val paymentHeader = buildPaymentHeader(signer, requirement, rpcBlockhashProvider)
        val finalResponse = execute(
            "GET",
            url,
            extraHeaders + (PAYMENT_SIGNATURE_HEADER to paymentHeader),
            body = null,
        )
        return X402GetResult(response = finalResponse, paymentSignatureSent = paymentHeader)
    }

    private fun execute(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray?,
    ): Response {
        val requestBody = body?.toRequestBody("application/octet-stream".toMediaType())
        val builder = Request.Builder().url(url).method(method, requestBody)
        for ((name, value) in headers) {
            builder.header(name, value)
        }
        return okHttp.newCall(builder.build()).execute()
    }

    companion object {
        const val PAYMENT_SIGNATURE_HEADER = "Payment-Signature"
    }
}

/**
 * Minimal Solana JSON-RPC blockhash provider for the x402 client.
 *
 * Only used when an offer omits ``extra.recentBlockhash`` (the pay_kit x402
 * server stamps the blockhash, so this is the rare path). Built on OkHttp to
 * avoid a heavyweight Solana client dependency.
 */
class X402RpcClient(
    private val url: String,
    private val okHttp: OkHttpClient = OkHttpClient(),
) {
    private val json = Json { ignoreUnknownKeys = true }

    /** Fetches the latest blockhash from a Solana JSON-RPC endpoint. Returns 32 bytes. */
    fun fetchRecentBlockhash(): ByteArray {
        val payload = buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", 1)
            put("method", "getLatestBlockhash")
        }
        val body = json.encodeToString(JsonObject.serializer(), payload)
            .toRequestBody("application/json".toMediaType())
        val request = Request.Builder().url(url).post(body).build()
        okHttp.newCall(request).execute().use { response ->
            val text = response.body?.string()
                ?: throw MppException.InvalidTransaction("empty RPC response")
            val parsed = try {
                json.parseToJsonElement(text)
            } catch (e: SerializationException) {
                throw MppException.InvalidTransaction(
                    "RPC response was not valid JSON (status ${response.code}): ${e.message ?: "parse error"}",
                )
            }
            if (parsed !is JsonObject) {
                throw MppException.InvalidTransaction("non-object RPC response")
            }
            val error = parsed["error"]
            if (error != null) {
                throw MppException.InvalidTransaction("RPC error: $error")
            }
            val blockhash = parsed["result"]?.jsonObject?.get("value")?.jsonObject
                ?.get("blockhash")?.jsonPrimitive?.content
                ?: throw MppException.InvalidTransaction("getLatestBlockhash returned no value")
            val decoded = try {
                Base58.decode(blockhash)
            } catch (e: MppException.InvalidBase58) {
                throw MppException.InvalidTransaction("Invalid blockhash from RPC: ${e.message}")
            }
            if (decoded.size != 32) {
                throw MppException.InvalidTransaction("Invalid blockhash length ${decoded.size} from RPC")
            }
            return decoded
        }
    }
}
