package com.solana.paykit.protocols.mpp.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) serializer.
 *
 * Produces a byte-for-byte canonical UTF-8 representation of a
 * `JsonElement` tree by:
 *
 *  - Sorting object keys lexicographically by UTF-16 code unit order
 *    (Array.prototype.sort semantics, per RFC 8785 sect. 3.2.3).
 *  - Emitting strings using the ES2017 / RFC 8785 escape rules.
 *  - Emitting numbers in their literal source form. Authorization
 *    credentials only carry string and structural values, so non
 *    integer numerics are intentionally rejected to keep the encoder
 *    aligned with the Rust `serde_json_canonicalizer` golden output.
 *  - Inserting no insignificant whitespace.
 *
 * This matches the Rust client's `format_authorization` output and the
 * canonical JCS test vectors so that conformance verifiers can hash or
 * sign the credential bytes directly.
 */
internal object CanonicalJson {
    fun encode(element: JsonElement): String {
        val builder = StringBuilder()
        write(element, builder)
        return builder.toString()
    }

    private fun write(element: JsonElement, builder: StringBuilder) {
        when (element) {
            is JsonNull -> builder.append("null")
            is JsonObject -> writeObject(element, builder)
            is JsonArray -> writeArray(element, builder)
            is JsonPrimitive -> writePrimitive(element, builder)
        }
    }

    private fun writeObject(value: JsonObject, builder: StringBuilder) {
        builder.append('{')
        // RFC 8785 sect. 3.2.3: sort by UTF-16 code unit order. Kotlin
        // String.compareTo is exactly that comparison.
        val sortedKeys = value.keys.sorted()
        sortedKeys.forEachIndexed { index, key ->
            if (index > 0) builder.append(',')
            writeString(key, builder)
            builder.append(':')
            write(value.getValue(key), builder)
        }
        builder.append('}')
    }

    private fun writeArray(value: JsonArray, builder: StringBuilder) {
        builder.append('[')
        value.forEachIndexed { index, item ->
            if (index > 0) builder.append(',')
            write(item, builder)
        }
        builder.append(']')
    }

    private fun writePrimitive(primitive: JsonPrimitive, builder: StringBuilder) {
        if (primitive.isString) {
            writeString(primitive.content, builder)
            return
        }
        val content = primitive.content
        if (content == "true" || content == "false" || content == "null") {
            builder.append(content)
            return
        }
        // Numbers: PaymentCredential only ever emits integer numerics
        // through kotlinx.serialization, so accept Long-shaped values
        // and reject anything else to avoid implementing the full
        // ES2017 number-to-string algorithm.
        val asLong = content.toLongOrNull()
        if (asLong != null) {
            builder.append(asLong.toString())
            return
        }
        throw IllegalArgumentException(
            "CanonicalJson does not support non-integer numeric primitive: $content",
        )
    }

    private fun writeString(value: String, builder: StringBuilder) {
        builder.append('"')
        var index = 0
        while (index < value.length) {
            val char = value[index]
            when (char) {
                '"' -> builder.append("\\\"")
                '\\' -> builder.append("\\\\")
                '\b' -> builder.append("\\b")
                '\u000C' -> builder.append("\\f")
                '\n' -> builder.append("\\n")
                '\r' -> builder.append("\\r")
                '\t' -> builder.append("\\t")
                else -> {
                    if (char.code < 0x20) {
                        builder.append("\\u")
                        builder.append(String.format("%04x", char.code))
                    } else {
                        builder.append(char)
                    }
                }
            }
            index += 1
        }
        builder.append('"')
    }
}
