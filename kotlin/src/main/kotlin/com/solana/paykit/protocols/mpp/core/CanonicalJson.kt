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
 *  - Emitting numbers with ECMAScript/IEEE-754 semantics, including negative
 *    zero, exponent thresholds, and integers above the exact 53-bit range.
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
        builder.append(formatEcmaNumber(content))
    }

    private fun formatEcmaNumber(literal: String): String {
        val value = literal.toDoubleOrNull()
            ?: throw IllegalArgumentException("CanonicalJson has an invalid numeric primitive: $literal")
        require(value.isFinite()) { "CanonicalJson requires a finite numeric primitive: $literal" }
        if (value == 0.0) return "0"

        val source = value.toString().lowercase()
        val sign = if (source.startsWith('-')) "-" else ""
        val unsigned = if (sign.isEmpty()) source else source.drop(1)
        val parts = unsigned.split('e', limit = 2)
        val exponent = if (parts.size == 2) parts[1].toIntOrNull() else 0
        require(exponent != null) { "CanonicalJson has an invalid numeric primitive: $literal" }

        val mantissa = parts[0]
        val point = mantissa.indexOf('.')
        val beforePoint = if (point >= 0) mantissa.substring(0, point) else mantissa
        val afterPoint = if (point >= 0) mantissa.substring(point + 1) else ""
        val allDigits = beforePoint + afterPoint
        val firstSignificant = allDigits.indexOfFirst { it != '0' }
        if (firstSignificant < 0) return "0"

        var digits = allDigits.substring(firstSignificant).trimEnd('0')
        val scientificExponent = exponent + beforePoint.length - 1 - firstSignificant
        if (scientificExponent in 0..20) {
            val integerDigits = scientificExponent + 1
            return if (digits.length <= integerDigits) {
                sign + digits + "0".repeat(integerDigits - digits.length)
            } else {
                sign + digits.substring(0, integerDigits) + "." + digits.substring(integerDigits)
            }
        }
        if (scientificExponent in -6..-1) {
            return sign + "0." + "0".repeat(-scientificExponent - 1) + digits
        }

        val first = digits.first()
        digits = digits.drop(1)
        val normalizedMantissa = if (digits.isEmpty()) first.toString() else "$first.$digits"
        val normalizedExponent = if (scientificExponent >= 0) "+$scientificExponent" else scientificExponent.toString()
        return sign + normalizedMantissa + "e" + normalizedExponent
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
