package org.solana.x402.exact

import com.google.gson.Gson
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.util.Base64

data class PaymentRequirement(
    val scheme: String,
    val network: String,
    val asset: String,
    val amount: String,
    val payTo: String? = null,
    val maxTimeoutSeconds: Int? = null,
    val extra: Map<String, JsonElement> = emptyMap(),
    val raw: JsonObject,
)

data class ResourceInfo(
    val url: String? = null,
    val description: String? = null,
    val mimeType: String? = null,
    val raw: JsonObject = JsonObject(),
)

data class SelectedChallenge(
    val requirement: PaymentRequirement,
    val resource: ResourceInfo? = null,
)

/**
 * Closed enumeration of the Solana networks recognised by the exact resolver.
 * Anything not in this set is treated as "unknown" and the resolver fails closed
 * rather than silently producing a mainnet mint address.
 */
sealed class SolanaNetwork(val caip2: String) {
    object Mainnet : SolanaNetwork("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpLcR4w9wpc")
    object Devnet : SolanaNetwork("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1")
    object Localnet : SolanaNetwork("solana:localnet")

    companion object {
        // Canonical CAIP-2 strings plus the historical "devnet" short string used by
        // the harness fixture (which the implementation has always treated as devnet).
        fun fromIdentifierOrNull(value: String): SolanaNetwork? = when (value) {
            Mainnet.caip2,
            "solana:mainnet",
            "solana-mainnet",
            "mainnet",
            "mainnet-beta",
            -> Mainnet
            Devnet.caip2,
            "solana:devnet",
            "solana-devnet",
            "devnet",
            -> Devnet
            Localnet.caip2,
            "localnet",
            -> Localnet
            else -> null
        }
    }
}

object ExactChallenge {
    // Default network used by the interop harness fixture — this is the Solana
    // devnet CAIP-2 genesis hash. Kept as a string for backwards compatibility
    // with callers that compare against it directly.
    const val DEFAULT_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    private val gson = Gson()

    fun selectSvmChallenge(
        headers: Map<String, String>,
        body: String?,
        network: String = DEFAULT_NETWORK,
        scheme: String = "exact",
        preferredCurrencies: List<String> = emptyList(),
    ): SelectedChallenge? {
        val envelopes = listOfNotNull(
            paymentRequiredHeader(headers),
            paymentRequiredBody(body),
        )

        for (envelope in envelopes) {
            val candidates = accepts(envelope)
                .filter { it.scheme == scheme && it.network == network }
                .filter { it.asset.isNotBlank() && it.amount.isNotBlank() }

            if (candidates.isEmpty()) {
                continue
            }

            val resource = resource(envelope)
            if (preferredCurrencies.isNotEmpty()) {
                for (currency in preferredCurrencies) {
                    val selected = candidates.firstOrNull {
                        currencyMatches(it.asset, currency, network) ||
                            currencyMatches(it.raw.string("currency"), currency, network)
                    }
                    if (selected != null) {
                        return SelectedChallenge(selected, resource)
                    }
                }
                continue
            }

            return SelectedChallenge(
                candidates.minBy { it.amount.toULongOrNull() ?: ULong.MAX_VALUE },
                resource,
            )
        }

        return null
    }

    private fun paymentRequiredHeader(headers: Map<String, String>): JsonObject? {
        val encoded = headers.entries
            .firstOrNull { it.key.equals("PAYMENT-REQUIRED", ignoreCase = true) }
            ?.value
            ?: return null

        return try {
            val decoded = String(Base64.getDecoder().decode(encoded), Charsets.UTF_8)
            JsonParser.parseString(decoded).asJsonObjectOrNull()
        } catch (_: RuntimeException) {
            null
        }
    }

    private fun paymentRequiredBody(body: String?): JsonObject? {
        if (body.isNullOrBlank()) {
            return null
        }

        return try {
            JsonParser.parseString(body).asJsonObjectOrNull()
        } catch (_: RuntimeException) {
            null
        }
    }

    private fun accepts(envelope: JsonObject): List<PaymentRequirement> {
        val accepts = envelope.get("accepts")?.asJsonArray ?: return emptyList()

        return accepts.mapNotNull { entry ->
            val obj = entry.asJsonObjectOrNull() ?: return@mapNotNull null
            val scheme = obj.string("scheme") ?: return@mapNotNull null
            val network = obj.string("network") ?: return@mapNotNull null
            val asset = obj.string("asset") ?: return@mapNotNull null
            val amount = obj.string("amount") ?: return@mapNotNull null
            PaymentRequirement(
                scheme = scheme,
                network = network,
                asset = asset,
                amount = amount,
                payTo = obj.string("payTo"),
                maxTimeoutSeconds = obj.get("maxTimeoutSeconds")?.takeIf { it.isJsonPrimitive }?.asInt,
                extra = obj.get("extra")?.asJsonObjectOrNull()?.entrySet()
                    ?.associate { it.key to it.value }
                    ?: emptyMap(),
                raw = obj,
            )
        }
    }

    private fun resource(envelope: JsonObject): ResourceInfo? {
        val obj = envelope.get("resource")?.asJsonObjectOrNull() ?: return null
        return ResourceInfo(
            url = obj.string("url"),
            description = obj.string("description"),
            mimeType = obj.string("mimeType"),
            raw = obj,
        )
    }

    private fun currencyMatches(offered: String?, accepted: String, network: String): Boolean {
        if (offered.isNullOrBlank()) {
            return false
        }
        // stablecoinMint fails closed on unknown networks for known symbols by
        // throwing IllegalArgumentException. In the context of preference matching
        // an unresolvable pair simply means "not a match" — never let the throw
        // escape and break the entire challenge-selection loop for unrelated
        // requirements.
        val offeredMint = runCatching { stablecoinMint(offered, network) }.getOrNull() ?: return false
        val acceptedMint = runCatching { stablecoinMint(accepted, network) }.getOrNull() ?: return false
        return offeredMint == acceptedMint
    }

    /**
     * Resolves a stablecoin symbol (USDC, PYUSD, USDG, USDT, CASH) to its mint address
     * on the given Solana network. Fail-closed by design: only the canonical CAIP-2
     * Solana network identifiers (mainnet, devnet, localnet) are accepted as network
     * inputs. Any other string is treated as either (a) an already-resolved mint that
     * gets returned verbatim, or (b) an unknown network that throws — never a silent
     * mainnet fallback. This closes the "bare-string devnet leaks mainnet mint" bug.
     */
    fun stablecoinMint(currency: String, network: String): String {
        val resolved = SolanaNetwork.fromIdentifierOrNull(network)
        if (resolved == null) {
            // Unknown network identifier — if the currency is already a non-symbolic
            // address-shaped string, pass it through (legacy behaviour for callers
            // that hand us a mint directly). Otherwise we must fail closed rather
            // than silently picking a mainnet address.
            val trimmed = currency.trim()
            val upper = trimmed.uppercase()
            if (upper in KNOWN_SYMBOLS) {
                throw IllegalArgumentException(
                    "Cannot resolve stablecoin symbol '$trimmed' on unknown network '$network'; " +
                        "use a CAIP-2 Solana network identifier (solana:<genesis-hash>) or " +
                        "pass a mint address directly.",
                )
            }
            return trimmed
        }
        return stablecoinMint(currency, resolved)
    }

    fun stablecoinMint(currency: String, network: SolanaNetwork): String {
        val trimmed = currency.trim()
        return when (trimmed.uppercase()) {
            "USDC", "USD" -> when (network) {
                SolanaNetwork.Mainnet -> "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
                SolanaNetwork.Devnet, SolanaNetwork.Localnet ->
                    "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
            }
            "PYUSD" -> when (network) {
                SolanaNetwork.Mainnet -> "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
                SolanaNetwork.Devnet, SolanaNetwork.Localnet ->
                    "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
            }
            "USDG" -> when (network) {
                SolanaNetwork.Mainnet -> "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
                SolanaNetwork.Devnet, SolanaNetwork.Localnet ->
                    "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
            }
            // USDT and CASH currently have no canonical devnet mint inside the
            // x402 SVM test matrix; the interop harness only exercises them on
            // mainnet, so we return the mainnet mint here and rely on the
            // mainnet-only network resolver to fail closed on any other cluster.
            "USDT" -> when (network) {
                SolanaNetwork.Mainnet -> "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
                SolanaNetwork.Devnet, SolanaNetwork.Localnet ->
                    throw IllegalArgumentException(
                        "USDT has no canonical mint on $network in this adapter; " +
                            "supply the mint address explicitly",
                    )
            }
            "CASH" -> when (network) {
                SolanaNetwork.Mainnet -> "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
                SolanaNetwork.Devnet, SolanaNetwork.Localnet ->
                    throw IllegalArgumentException(
                        "CASH has no canonical mint on $network in this adapter; " +
                            "supply the mint address explicitly",
                    )
            }
            else -> trimmed
        }
    }

    private val KNOWN_SYMBOLS = setOf("USDC", "USD", "PYUSD", "USDG", "USDT", "CASH")

    fun resultJson(
        ok: Boolean,
        status: Int,
        responseHeaders: Map<String, String> = emptyMap(),
        responseBody: Any? = null,
        settlement: Any? = null,
        error: String? = null,
    ): String {
        val payload = linkedMapOf<String, Any?>(
            "type" to "result",
            "implementation" to "kotlin",
            "role" to "client",
            "ok" to ok,
            "status" to status,
            "responseHeaders" to responseHeaders,
            "responseBody" to responseBody,
        )
        if (error != null) {
            payload["error"] = error
        }
        if (settlement != null) {
            payload["settlement"] = settlement
        }
        return gson.toJson(payload)
    }
}

private fun JsonElement.asJsonObjectOrNull(): JsonObject? =
    if (isJsonObject) asJsonObject else null

private fun JsonObject.string(name: String): String? =
    get(name)?.takeIf { it.isJsonPrimitive }?.asString
