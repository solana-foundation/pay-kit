package com.solana.mpp

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
        val wwwAuthenticate = initial.header(WWW_AUTHENTICATE_HEADER)
            ?: throw MppException.InvalidPaymentScheme
        initial.close()
        val challenge = MppHeaders.parseWWWAuthenticate(wwwAuthenticate)
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
            val parsed = json.parseToJsonElement(text)
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
