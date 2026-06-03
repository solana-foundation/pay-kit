package com.solana.paykit.protocols.x402.client.exact

import com.solana.paykit.paycore.*

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

/**
 * Minimal Solana JSON-RPC blockhash provider for the x402 client.
 *
 * Only used when an offer omits ``extra.recentBlockhash`` (the pay_kit x402
 * server stamps the blockhash, so this is the rare path). Built on OkHttp to
 * avoid a heavyweight Solana client dependency. Wire it into a client via
 * ``PayKitClient.Builder.x402(rpc = ...)`` or pass
 * ``{ rpcClient.fetchRecentBlockhash() }`` to the lambda overload.
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
