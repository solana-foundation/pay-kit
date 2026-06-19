package com.solana.paykit.demo

import androidx.compose.ui.graphics.Color
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.math.BigDecimal
import java.math.RoundingMode

/**
 * A priced operation discovered from the playground's `/openapi.json`,
 * rendered as a tappable card in the endpoints collection. Mirrors the
 * iOS demo's `Endpoint` value type.
 */
data class Endpoint(
    val id: String,
    val label: String,
    val method: String,
    val path: String,
    val priceUsd: String,
    val tint: Color,
)

/**
 * Decodes the playground's `GET /openapi.json` discovery document into the
 * app's `List<Endpoint>` collection.
 *
 * The document is an OpenAPI 3.1 doc whose every priced operation under
 * `paths.<path>.<httpMethod>` carries an `x-payment-info` extension with an
 * `offers[]` list (the payment-discovery draft: `intent` / `method` / `amount`
 * per offer, plus pay-kit extras like `scheme` / `network` / `payTo`).
 * Operations with no `x-payment-info` (health, `/openapi.json`, docs) are free
 * and excluded.
 *
 * Parsing goes through `kotlinx.serialization`'s untyped `JsonObject` tree
 * (with `ignoreUnknownKeys`) rather than `@Serializable` data classes, because
 * the hyphenated extension keys and arbitrarily-nested offers array are awkward
 * for generated decoders. This mirrors the iOS demo's `JSONSerialization` path.
 */
object OpenApi {
    private val json = Json { ignoreUnknownKeys = true }

    /** HTTP verbs that can carry an operation object in an OpenAPI path item. */
    private val HTTP_METHODS = setOf("get", "post", "put", "patch", "delete", "head", "options")

    /**
     * Cycle through a fixed palette so each card gets a distinct tint. Matches
     * the iOS palette order so the two demos read the same.
     */
    private val PALETTE = listOf(
        Color(0xFF0A84FF), // blue
        Color(0xFF5E5CE6), // indigo
        Color(0xFFAF52DE), // purple
        Color(0xFFFF2D55), // pink
        Color(0xFFFF9500), // orange
        Color(0xFF34C759), // green
        Color(0xFFFF3B30), // red
        Color(0xFF30B0C7), // teal
    )

    /**
     * Build the priced-endpoint collection from a raw `/openapi.json` body.
     * Returns endpoints in a stable order (sorted by path then method) so the
     * per-index tint and layout do not reshuffle between loads.
     */
    fun endpoints(from: String): List<Endpoint> {
        val root = json.parseToJsonElement(from).jsonObject
        val paths = root["paths"]?.jsonObject ?: throw OpenApiException("openapi.json had no `paths`.")

        data class Parsed(val path: String, val method: String, val operation: JsonObject)

        val parsed = mutableListOf<Parsed>()
        for ((path, item) in paths) {
            val operations = item as? JsonObject ?: continue
            for ((method, op) in operations) {
                if (method.lowercase() !in HTTP_METHODS) continue
                val operation = op as? JsonObject ?: continue
                // Only priced operations are tappable. Free routes (health,
                // docs, /openapi.json) carry no `x-payment-info`.
                operation["x-payment-info"] as? JsonObject ?: continue
                parsed.add(Parsed(path, method.uppercase(), operation))
            }
        }

        parsed.sortWith(compareBy({ it.path }, { it.method }))

        return parsed.mapIndexed { index, entry ->
            endpoint(entry.path, entry.method, entry.operation, index)
        }
    }

    private fun endpoint(path: String, method: String, operation: JsonObject, index: Int): Endpoint {
        val paymentInfo = operation["x-payment-info"]?.jsonObject
        val firstOffer = paymentInfo?.get("offers")?.jsonArray?.firstOrNull()?.jsonObject

        val summary = (operation["summary"] as? JsonPrimitive)?.contentOrNull?.trim()
        val label = if (!summary.isNullOrEmpty()) summary else path

        return Endpoint(
            id = "$method $path",
            label = label,
            method = method,
            path = requestPath(path),
            priceUsd = priceString(firstOffer),
            tint = PALETTE[index % PALETTE.size],
        )
    }

    /**
     * Turn a templated OpenAPI path (`/api/v1/quote/{symbol}`) into a concrete
     * request path by filling each `{param}` with a `demo` placeholder, so the
     * URL reaches the mounted route instead of 404-ing on the literal
     * `{symbol}` segment.
     */
    fun requestPath(openApiPath: String): String {
        if (!openApiPath.contains('{')) return openApiPath
        val result = StringBuilder()
        var insideParam = false
        for (char in openApiPath) {
            when (char) {
                '{' -> {
                    insideParam = true
                    result.append("demo")
                }
                '}' -> insideParam = false
                else -> if (!insideParam) result.append(char)
            }
        }
        return result.toString()
    }

    /**
     * Format the offer price as a dollar string. The offer's `amount` is a
     * base-unit integer string (USDC has 6 decimals); fall back to the
     * human-readable `description` (e.g. `"0.01 USDC"`) and finally a dash.
     */
    fun priceString(offer: JsonObject?): String {
        val amount = (offer?.get("amount") as? JsonPrimitive)?.contentOrNull
        val baseUnits = amount?.toBigDecimalOrNull()
        if (baseUnits != null) {
            val dollars = baseUnits
                .divide(BigDecimal(1_000_000))
                .setScale(2, RoundingMode.HALF_UP)
                .stripTrailingZerosOrTwo()
            val prefix = if ((offer["scheme"] as? JsonPrimitive)?.contentOrNull == "upto") "up to " else ""
            return "$prefix$$dollars"
        }
        val description = (offer?.get("description") as? JsonPrimitive)?.contentOrNull
        if (!description.isNullOrEmpty()) return description
        return "—"
    }

    private fun String.toBigDecimalOrNull(): BigDecimal? =
        try {
            BigDecimal(this)
        } catch (_: NumberFormatException) {
            null
        }

    /** Keep at least 2 fraction digits (so `$0.01`), but allow more when present. */
    private fun BigDecimal.stripTrailingZerosOrTwo(): String {
        val stripped = stripTrailingZeros()
        val scale = stripped.scale().coerceAtLeast(2)
        return stripped.setScale(scale, RoundingMode.HALF_UP).toPlainString()
    }
}

/** Failure mode when decoding `/openapi.json`. */
class OpenApiException(message: String) : Exception(message)
