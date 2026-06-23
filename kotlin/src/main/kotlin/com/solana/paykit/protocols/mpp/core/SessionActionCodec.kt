package com.solana.paykit.protocols.mpp.core

import com.solana.paykit.paycore.MppException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

/**
 * Codec for the internally-tagged [SessionAction] union: encodes the payload to
 * a JSON object and injects the `action` discriminator alongside the payload's
 * own fields (flattened), and decodes by reading `action` then the remaining
 * fields. Mirrors the Rust serde internally-tagged enum and the Go SessionAction
 * JSON. The TopUp tag is camelCase `topUp`.
 */
object SessionActionCodec {
    private val json = Json {
        encodeDefaults = false
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    fun toJsonObject(action: SessionAction): JsonObject {
        val (tag, element) = when (action) {
            is SessionAction.Open -> "open" to json.encodeToJsonElement(action.payload)
            is SessionAction.Voucher -> "voucher" to json.encodeToJsonElement(action.payload)
            is SessionAction.Commit -> "commit" to json.encodeToJsonElement(action.payload)
            is SessionAction.TopUp -> "topUp" to json.encodeToJsonElement(action.payload)
            is SessionAction.Close -> "close" to json.encodeToJsonElement(action.payload)
        }
        return buildJsonObject {
            put("action", JsonPrimitive(tag))
            for ((key, value) in element.jsonObject) put(key, value)
        }
    }

    fun fromJsonObject(obj: JsonObject): SessionAction {
        val tag = (obj["action"] as? JsonPrimitive)?.content
            ?: throw MppException.InvalidJson()
        val rest = JsonObject(obj.filterKeys { it != "action" })
        return when (tag) {
            "open" -> SessionAction.Open(json.decodeFromJsonElement(OpenPayload.serializer(), rest))
            "voucher" -> SessionAction.Voucher(json.decodeFromJsonElement(VoucherPayload.serializer(), rest))
            "commit" -> SessionAction.Commit(json.decodeFromJsonElement(CommitPayload.serializer(), rest))
            "topUp" -> SessionAction.TopUp(json.decodeFromJsonElement(TopUpPayload.serializer(), rest))
            "close" -> SessionAction.Close(json.decodeFromJsonElement(ClosePayload.serializer(), rest))
            else -> throw MppException.InvalidTransaction("unknown session action: $tag")
        }
    }

    fun encodeToString(action: SessionAction): String =
        json.encodeToString(JsonObject.serializer(), toJsonObject(action))

    fun decodeFromString(text: String): SessionAction =
        fromJsonObject(json.parseToJsonElement(text).jsonObject)
}
