package com.solana.mpp.client

import com.solana.mpp.protocol.*
import com.solana.mpp.crypto.*

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
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
 * MPP-aware HTTP client built on OkHttp.
 *
 * On a 402 Payment Required response the client:
 *
 * 1. Parses the `WWW-Authenticate: Payment ...` challenge header.
 * 2. Decodes the Solana charge request from the challenge.
 * 3. Builds and signs the transaction through Charge.buildCredentialHeader.
 * 4. Replays the original request with an `Authorization: Payment ...`
 *    header and returns the 200 response.
 *
 * The retry is single-shot. The client deliberately does not retry on
 * 5xx, network errors, or other 4xx statuses: the MPP flow only
 * applies to 402.
 */
class MppHttpClient(
    private val signer: SolanaSigner,
    private val blockhashProvider: BlockhashProvider,
    private val okHttp: OkHttpClient = OkHttpClient(),
    private val computeUnitLimit: Int = 200_000,
    private val computeUnitPrice: Long = 1L,
) {
    /**
     * Performs an MPP-aware GET. Returns the response from the post-payment
     * exchange when the server initially answered 402; otherwise returns
     * the original response. Callers are responsible for closing the
     * response body.
     */
    fun mppGet(url: String, headers: Map<String, String> = emptyMap()): Response {
        val initial = execute("GET", url, headers, body = null)
        if (initial.code != 402) {
            return initial
        }
        // The 402 response is consumed here regardless of whether the
        // server actually returned a WWW-Authenticate header. The previous
        // implementation read the header and threw on the missing-header
        // branch without closing the body, which leaked the underlying
        // OkHttp connection on every malformed 402 (see Greptile comment
        // 3293054077). The Response.use { ... } block guarantees the body
        // is closed deterministically on both branches.
        //
        // Per RFC 9110 a 402 may advertise multiple `WWW-Authenticate`
        // challenges, either as several separate header lines or as a
        // single comma-joined header value, and Payment can appear
        // alongside other schemes such as Basic, Bearer, or x402. We
        // walk every advertised challenge and select the first Solana
        // charge Payment challenge so the client never aborts when a
        // non-Solana scheme happens to come first in the response.
        val advertised = initial.use { response ->
            response.headers(WWW_AUTHENTICATE_HEADER)
        }
        if (advertised.isEmpty()) {
            throw MppException.InvalidPaymentScheme
        }
        val challenge = MppHeaders.selectSolanaChargeChallenge(advertised)
            ?: throw MppException.InvalidPaymentScheme
        val authorization = Charge.buildCredentialHeader(
            signer = signer,
            challenge = challenge,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
        )
        return execute(
            "GET",
            url,
            headers + (AUTHORIZATION_HEADER to authorization),
            body = null,
        )
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
        const val WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"
        const val AUTHORIZATION_HEADER = "Authorization"
    }
}

/**
 * Minimal Solana JSON-RPC client used by the interop adapter to fetch
 * a recent blockhash when the challenge does not pin one. Built on
 * OkHttp so the SDK does not pick up a heavyweight Solana stack as a
 * runtime dependency.
 */
class JsonRpcClient(
    private val url: String,
    private val okHttp: OkHttpClient = OkHttpClient(),
) : BlockhashProvider {
    private val json = Json { ignoreUnknownKeys = true }

    /** Fetches the latest blockhash from a Solana JSON-RPC endpoint. */
    override fun fetchRecentBlockhash(): ByteArray {
        val payload = buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", 1)
            put("method", "getLatestBlockhash")
        }
        val response = post(payload)
        val blockhash = response["result"]?.jsonObject?.get("value")?.jsonObject
            ?.get("blockhash")?.jsonPrimitive?.content
            ?: throw MppException.InvalidTransaction("getLatestBlockhash returned no value")
        val decoded = try {
            Base58.decode(blockhash)
        } catch (e: MppException.InvalidBase58) {
            throw MppException.InvalidTransaction("Invalid blockhash from RPC: ${e.message}")
        }
        if (decoded.size != 32) {
            throw MppException.InvalidTransaction(
                "Invalid blockhash length ${decoded.size} from RPC",
            )
        }
        return decoded
    }

    /** Submits a signed Solana transaction via JSON-RPC and returns the signature. */
    fun sendTransaction(base64Transaction: String): String {
        val payload = buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", 1)
            put("method", "sendTransaction")
            put(
                "params",
                buildJsonArray {
                    add(JsonPrimitive(base64Transaction))
                    add(
                        buildJsonObject {
                            put("encoding", "base64")
                            put("skipPreflight", false)
                        },
                    )
                },
            )
        }
        val response = post(payload)
        return response["result"]?.jsonPrimitive?.content
            ?: throw MppException.InvalidTransaction("sendTransaction returned no result")
    }

    private fun post(payload: JsonObject): JsonObject {
        val body = json.encodeToString(JsonObject.serializer(), payload)
            .toRequestBody("application/json".toMediaType())
        val request = Request.Builder().url(url).post(body).build()
        okHttp.newCall(request).execute().use { response ->
            val text = response.body?.string()
                ?: throw MppException.InvalidTransaction("empty RPC response")
            // Guard the JSON parse so a non-JSON RPC response (e.g. an
            // HTML 503 page from a load balancer during a node restart)
            // surfaces as the structured MppException.InvalidTransaction
            // that every other branch already raises. Without this
            // wrapper, callers catching MppException to handle network
            // failures would silently miss a raw SerializationException
            // bubbling up from kotlinx.serialization.
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
            return parsed
        }
    }

}
