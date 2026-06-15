package com.solana.paykit.protocols.mpp.core

import com.solana.paykit.paycore.*

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement

/** Parses and formats MPP HTTP Payment headers. */
object MppHeaders {
    /** HTTP authentication scheme used by MPP. */
    const val PAYMENT_SCHEME = "Payment"

    /**
     * Maximum byte length of the base64url `request` parameter before it is
     * decoded and JSON-parsed. Mirrors the rust parser's `MAX_TOKEN_LEN = 16 *
     * 1024` (audit #9): the `request` param is the only `WWW-Authenticate`
     * field that drives O(n) base64-decode + JSON-parse cost, so an uncapped
     * value lets a hostile server force proportionally large decode/parse work.
     * Every other auth-param (id/realm/method/intent/expires/digest/opaque) is
     * a short pass-through string.
     */
    const val MAX_TOKEN_LEN = 16 * 1024

    private val json = Json {
        encodeDefaults = false
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    /**
     * Splits a single `WWW-Authenticate` header value into the
     * individual challenges it advertises. RFC 9110 lets a server
     * comma-join multiple challenges into one header line, so we
     * cannot assume one header value carries exactly one challenge.
     *
     * The split walks the value character by character and treats a
     * comma as a separator only when it is outside a quoted string and
     * the next non-space token looks like a scheme name followed by a
     * space (RFC 7235 challenge grammar). That keeps comma-bearing
     * auth-param values such as the base64url request payload or
     * quoted realm strings intact while still recovering each scheme
     * the server actually advertised.
     */
    fun splitChallenges(header: String): List<String> {
        val commaPositions = mutableListOf<Int>()
        var inQuotes = false
        var escaped = false
        for ((index, char) in header.withIndex()) {
            when {
                escaped -> escaped = false
                char == '\\' && inQuotes -> escaped = true
                char == '"' -> inQuotes = !inQuotes
                char == ',' && !inQuotes -> commaPositions.add(index)
            }
        }

        val boundaries = mutableListOf(0)
        for (pos in commaPositions) {
            var cursor = pos + 1
            while (cursor < header.length && header[cursor].isWhitespace()) {
                cursor += 1
            }
            val schemeStart = cursor
            while (cursor < header.length && isTokenChar(header[cursor])) {
                cursor += 1
            }
            // A real new challenge requires a token followed by at
            // least one HTTP whitespace char (SP or HTAB per RFC 7230);
            // if the next token is followed by `=` we are still inside
            // the previous challenge's auth-param list. `isWhitespace()`
            // covers both SP and HTAB so we don't miss tab-separated
            // challenges from compliant peers.
            if (cursor > schemeStart && cursor < header.length && header[cursor].isWhitespace()) {
                boundaries.add(pos + 1)
            }
        }
        boundaries.add(header.length + 1)

        val results = mutableListOf<String>()
        for (i in 0 until boundaries.size - 1) {
            val start = boundaries[i]
            val end = (boundaries[i + 1] - 1).coerceAtMost(header.length)
            val slice = header.substring(start, end).trim().trimEnd(',').trim()
            if (slice.isNotEmpty()) {
                results.add(slice)
            }
        }
        return results
    }

    private fun isTokenChar(char: Char): Boolean {
        if (char.isLetterOrDigit()) return true
        return char in "!#$%&'*+-.^_`|~"
    }

    /**
     * Selects the Solana charge Payment challenge from a set of
     * `WWW-Authenticate` header values, transparently handling both
     * the multi-header and comma-joined forms. Returns null when no
     * advertised challenge targets `method="solana"` /
     * `intent="charge"`.
     */
    fun selectSolanaChargeChallenge(headers: List<String>): PaymentChallenge? {
        for (header in headers) {
            for (raw in splitChallenges(header)) {
                val trimmed = raw.trim()
                if (!trimmed.startsWith(PAYMENT_SCHEME, ignoreCase = true)) {
                    continue
                }
                val challenge = try {
                    parseWWWAuthenticate(trimmed)
                } catch (_: MppException) {
                    continue
                }
                if (challenge.method == "solana" && challenge.intent == "charge") {
                    return challenge
                }
            }
        }
        return null
    }

    /** Parses a `WWW-Authenticate: Payment ...` challenge header. */
    fun parseWWWAuthenticate(header: String): PaymentChallenge {
        val rest = paymentSchemePayload(header)
        val params = parseAuthParams(rest)
        val request = params["request"] ?: throw MppException.MissingField("request")
        // Cap the request param before base64-decoding + JSON-parsing it
        // (audit #9). Checked here (the parse entry point) and again in
        // decodeChargeRequest so the cap holds regardless of how a challenge
        // reaches the decode path.
        if (request.length > MAX_TOKEN_LEN) {
            throw MppException.InvalidHeader
        }

        return PaymentChallenge(
            id = params["id"] ?: throw MppException.MissingField("id"),
            realm = params["realm"] ?: throw MppException.MissingField("realm"),
            method = params["method"] ?: throw MppException.MissingField("method"),
            intent = params["intent"] ?: throw MppException.MissingField("intent"),
            request = request,
            expires = params["expires"],
            digest = params["digest"],
            opaque = params["opaque"],
        ).also {
            Base64Url.decode(request)
        }
    }

    /**
     * Formats an `Authorization: Payment ...` credential header.
     *
     * Credentials are serialized through the RFC 8785 JSON
     * Canonicalization Scheme before base64url encoding so the wire
     * bytes match the Rust client (`serde_json_canonicalizer`) and any
     * verifier that signs or digests the credential serialization
     * rather than only decoding the JSON. Using kotlinx.serialization's
     * declaration order would otherwise produce a different token for
     * the same credential, breaking byte-for-byte conformance.
     */
    fun formatAuthorization(credential: PaymentCredential): String {
        val tree = json.encodeToJsonElement(PaymentCredential.serializer(), credential)
        val canonical = CanonicalJson.encode(tree)
        val encoded = Base64Url.encode(canonical.encodeToByteArray())
        return "$PAYMENT_SCHEME $encoded"
    }

    internal fun decodeChargeRequest(request: String): ChargeRequest {
        // Cap the base64url payload before decode + JSON parse (audit #9).
        // A PaymentChallenge can be constructed directly (e.g. in tests or by
        // a caller that bypasses parseWWWAuthenticate), so the cap is enforced
        // here too rather than relying solely on the parse-time check.
        if (request.length > MAX_TOKEN_LEN) {
            throw MppException.InvalidHeader
        }
        return try {
            json.decodeFromString<ChargeRequest>(Base64Url.decode(request).decodeToString())
        } catch (error: IllegalArgumentException) {
            throw MppException.InvalidJson(error)
        } catch (error: kotlinx.serialization.SerializationException) {
            throw MppException.InvalidJson(error)
        }
    }

    private fun paymentSchemePayload(header: String): String {
        val trimmed = header.trim()
        if (!trimmed.startsWith(PAYMENT_SCHEME, ignoreCase = true)) {
            throw MppException.InvalidPaymentScheme
        }
        return trimmed.drop(PAYMENT_SCHEME.length).trim()
    }

    private fun parseAuthParams(value: String): Map<String, String> {
        val params = mutableMapOf<String, String>()
        var index = 0

        while (index < value.length) {
            while (index < value.length && (value[index].isWhitespace() || value[index] == ',')) {
                index += 1
            }
            if (index >= value.length) break

            val keyStart = index
            while (index < value.length && value[index] != '=') {
                index += 1
            }
            if (index >= value.length) throw MppException.InvalidHeader
            val key = value.substring(keyStart, index).trim()
            index += 1

            if (index >= value.length) throw MppException.InvalidHeader

            val rawValue: String
            if (value[index] == '"') {
                index += 1
                val decoded = StringBuilder()
                var escaped = false
                var closed = false
                while (index < value.length) {
                    val char = value[index]
                    index += 1
                    when {
                        escaped -> {
                            decoded.append(char)
                            escaped = false
                        }
                        char == '\\' -> escaped = true
                        char == '"' -> {
                            closed = true
                            break
                        }
                        else -> decoded.append(char)
                    }
                }
                if (!closed || escaped) throw MppException.InvalidHeader
                rawValue = decoded.toString()
            } else {
                // RFC 7235: auth-param value = token / quoted-string.
                // Compliant peers (Rust ref included) emit short token
                // values like `method=solana` unquoted. The Rust
                // reference parses both forms; matching it keeps
                // harness healthy.
                val valueStart = index
                while (index < value.length && !value[index].isWhitespace() && value[index] != ',') {
                    index += 1
                }
                if (index == valueStart) throw MppException.InvalidHeader
                rawValue = value.substring(valueStart, index)
            }

            // Rust reference rejects duplicate auth-params; silently
            // overwriting matters for challenge-echo integrity (`id`,
            // `request`, `digest`, `opaque`) and would let a hostile
            // header swap critical fields without detection.
            if (params.containsKey(key)) {
                throw MppException.InvalidHeader
            }
            params[key] = rawValue
        }

        return params
    }
}
