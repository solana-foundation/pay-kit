package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.protocols.mpp.core.*
import com.solana.paykit.paycore.*

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

/**
 * Minimal Solana JSON-RPC client used by the harness adapter to fetch
 * a recent blockhash when the challenge does not pin one. Built on
 * OkHttp so the SDK does not pick up a heavyweight Solana stack as a
 * runtime dependency.
 */
class JsonRpcClient(
    private val url: String,
    private val okHttp: OkHttpClient = OkHttpClient(),
) : BlockhashProvider, MintOwnerResolver {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Resolves the owning program of [mintBase58] via `getAccountInfo`.
     *
     * Used by the charge builder to determine the token program for a mint
     * when the challenge omits `methodDetails.tokenProgram` (mirrors the rust
     * client `resolve_token_program`, which reads the mint account owner).
     * Returns the base58 owner program id. Throws
     * [MppException.InvalidTransaction] if the account is missing or the RPC
     * response lacks an owner (fail-closed; the caller rejects the charge).
     */
    override fun fetchMintOwner(mintBase58: String): String {
        val payload = buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", 1)
            put("method", "getAccountInfo")
            put(
                "params",
                buildJsonArray {
                    add(JsonPrimitive(mintBase58))
                    add(
                        buildJsonObject {
                            put("encoding", "base64")
                        },
                    )
                },
            )
        }
        val response = post(payload)
        val value = response["result"]?.jsonObject?.get("value")
        if (value == null || value is kotlinx.serialization.json.JsonNull) {
            throw MppException.InvalidTransaction(
                "getAccountInfo returned no account for mint $mintBase58",
            )
        }
        return value.jsonObject["owner"]?.jsonPrimitive?.content
            ?: throw MppException.InvalidTransaction(
                "getAccountInfo returned no owner for mint $mintBase58",
            )
    }

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
