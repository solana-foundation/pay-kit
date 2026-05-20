package com.solana.mpp

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object MppHeaders {
    const val PAYMENT_SCHEME = "Payment"

    private val json = Json {
        encodeDefaults = false
        explicitNulls = false
    }

    fun parseWWWAuthenticate(header: String): PaymentChallenge {
        val rest = paymentSchemePayload(header)
        val params = parseAuthParams(rest)
        val request = params["request"] ?: throw MppException.MissingField("request")

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

    fun formatAuthorization(credential: PaymentCredential): String {
        val encoded = Base64Url.encode(json.encodeToString(credential).encodeToByteArray())
        return "$PAYMENT_SCHEME $encoded"
    }

    internal fun decodeChargeRequest(request: String): ChargeRequest =
        try {
            json.decodeFromString<ChargeRequest>(Base64Url.decode(request).decodeToString())
        } catch (error: IllegalArgumentException) {
            throw MppException.InvalidJson(error)
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

            if (index >= value.length || value[index] != '"') {
                throw MppException.InvalidHeader
            }
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
            params[key] = decoded.toString()
        }

        return params
    }
}
