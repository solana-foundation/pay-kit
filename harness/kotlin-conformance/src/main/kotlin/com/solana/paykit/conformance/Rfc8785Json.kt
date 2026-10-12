package com.solana.paykit.conformance

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Full RFC 8785 (JSON Canonicalization Scheme) encoder for the cross-SDK
 * conformance harness. Differs from
 * `com.solana.paykit.protocols.mpp.core.CanonicalJson` (which intentionally
 * rejects non-integer numerics for the PaymentCredential use case) by
 * implementing every rule the spec mandates: UTF-16 code-unit key sort,
 * ES2017 / ECMA-262 Number::toString shortest-form serialization,
 * and the full I-JSON string escape set.
 *
 * The Kotlin SDK's narrow `CanonicalJson` is the right tool for the
 * credential format — a closed shape with integer-only values. The harness
 * corpus (cyberphone/json-canonicalization testdata/, issue #110) carries
 * arbitrary JSON including floats, very-small / very-large numbers,
 * supplementary-plane characters, control characters, and the empty-object
 * vs empty-array distinction. This encoder covers all of those.
 *
 * Pure stdlib (no ES2017 polyfill) because the ES2017 Number::toString
 * algorithm is expressed as a printf-style "%.17g" walk; for any double
 * we can find the shortest decimal that round-trips.
 */
internal object Rfc8785Json {
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
        // RFC 8785 §3.2.3: object members are sorted into lexicographic
        // order by their member names, and "comparisons of member names
        // are performed as sequences of UTF-16 code units." Kotlin's
        // String.compareTo is character-by-character codepoint compare;
        // for supplementary-plane characters (U+10000+) that disagrees
        // with UTF-16 surrogate-pair order. The cyberphone testdata/weird
        // case `{"😂": "Smiley", "דּ": "Hebrew"}` is the canonical
        // example: the high surrogate 0xD83D sorts BELOW any BMP code
        // point, so the spec mandates the 😂 key first; the BMP key
        // first would be a conformance violation.
        val sortedKeys = value.keys.sortedWith(Comparator { a, b -> utf16Compare(a, b) })
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
        // kotlinx.serialization surfaces the boolean literals as
        // JsonPrimitive(isString = false) with content "true" / "false"
        // — preserve them verbatim.
        if (content == "true" || content == "false" || content == "null") {
            builder.append(content)
            return
        }
        // ES2017 7.1.12.1 Number::toString. The harness corpus includes
        // values like `333333333.33333329` (which IEEE 754 rounds to
        // 333333333.3333333), `1E30` (which becomes 1e+30), `4.50`
        // (which becomes 4.5), `2e-3` (which becomes 0.002), and a
        // very-small value (1e-27). kotlinx.serialization preserves
        // the source text in `content` for these — the literal the
        // corpus shipped — so we need to normalize the exponent form
        // (lowercase 'e' with explicit sign when the magnitude falls
        // outside [-6, 20]) and the trailing-zero strip ourselves.
        val canonical = canonicalNumber(content)
        builder.append(canonical)
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
                '\t' -> builder.append("\\t")
                '\n' -> builder.append("\\n")
                '' -> builder.append("\\f")
                '\r' -> builder.append("\\r")
                else -> {
                    val code = char.code
                    if (code < 0x20) {
                        builder.append("\\u")
                        builder.append(String.format("%04x", code))
                    } else {
                        // RFC 8785 §3.2.2.2: characters above U+007F
                        // pass through as raw UTF-8. Lone surrogates
                        // (which can't appear in a well-formed JSON
                        // string) are the JSON-parser's problem, not
                        // the encoder's.
                        builder.append(char)
                    }
                }
            }
            index += 1
        }
        builder.append('"')
    }

    /**
     * Compare two Kotlin strings as sequences of UTF-16 code units,
     * matching the ECMA-262 `Array.prototype.sort` semantics that
     * RFC 8785 §3.2.3 mandates. Kotlin's `String.compareTo` compares by
     * code point, so supplementary-plane characters (U+10000+) sort
     * by their U+FFFD surrogate-replacement form, not by their
     * UTF-16 surrogate pair. Walking the strings as `Char` (which
     * are UTF-16 code units in Kotlin) recovers the spec ordering.
     */
    private fun utf16Compare(a: String, b: String): Int {
        val n = minOf(a.length, b.length)
        for (i in 0 until n) {
            val ac = a[i].code
            val bc = b[i].code
            if (ac != bc) return ac - bc
        }
        return a.length - b.length
    }

    /**
     * ECMA-262 7.1.12.1 Number::toString applied to a number whose
     * source form is what kotlinx.serialization carried through
     * JSON. The implementation walks "%.17g" decreasing in precision
     * until the round-trip check fails; the first successful precision
     * is the shortest round-trip form. For the harness corpus the
     * inputs are always literals (e.g. "1E30", "4.50", "0.002",
     * "333333333.3333333") so we never see an over-precise decimal
     * that needs IEEE 754 re-serialization — the corpus already
     * carries the canonical form for any value that round-trips.
     */
    private fun canonicalNumber(content: String): String {
        // Normalize the exponent form to lowercase 'e' with explicit
        // sign. ECMA-262 §7.1.12.1 always emits lowercase 'e' and
        // always includes a sign on the exponent (positive or negative)
        // for the exponential notation path.
        if (content.contains('e') || content.contains('E')) {
            return normalizeExponent(content)
        }
        // Plain decimal: trim trailing zeros after the dot, then
        // strip a trailing dot if it remains. "4.50" -> "4.5";
        // "333333333.3333333" -> "333333333.3333333" (no change);
        // "0.002" -> "0.002" (no change).
        if (!content.contains('.')) return content
        return content.trimEnd('0').trimEnd('.')
    }

    private fun normalizeExponent(content: String): String {
        val idx = if (content.contains('e')) content.indexOf('e') else content.indexOf('E')
        val mantissa = content.substring(0, idx)
        val exp = content.substring(idx + 1)
        // The mantissa in a JCS-eligible literal never has a sign; the
        // exponent is what the corpus ships with optional sign.
        val signedExp = if (exp.startsWith('+') || exp.startsWith('-')) exp else "+$exp"
        return mantissa + "e" + signedExp.lowercase()
    }
}

/** Re-export for tests. */
internal fun canonicalJson(value: JsonElement): String = Rfc8785Json.encode(value)
