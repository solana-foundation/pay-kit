package org.solana.x402.exact

import com.google.gson.Gson
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import java.util.Base64

const val PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
const val MAX_MEMO_BYTES = 256

data class SolanaExactPaymentRequest(
    val payer: String,
    val network: String,
    val asset: String,
    val amount: String,
    val payTo: String,
    /**
     * Optional managed fee payer. Mirrors the Rust spine client at
     * rust/crates/x402/src/client/exact/payment.rs which falls back to the
     * signer (`payer`) as the actual transaction fee payer when
     * `requirements.fee_payer_key` is absent.
     */
    val feePayer: String?,
    val memo: String?,
    val maxTimeoutSeconds: Int?,
    val accepted: JsonObject,
)

data class UnsignedSolanaTransaction(
    val message: ByteArray,
    val signatures: List<ByteArray>,
    val signerIndex: Int,
) {
    init {
        require(message.isNotEmpty()) { "message is required" }
        require(signatures.isNotEmpty()) { "at least one signature slot is required" }
        require(signerIndex in signatures.indices) { "signerIndex is outside signature slots" }
        signatures.forEach { signature ->
            require(signature.size == SIGNATURE_LENGTH) { "signature slots must be 64 bytes" }
        }
    }

    fun signedWith(signature: ByteArray): ByteArray {
        require(signature.size == SIGNATURE_LENGTH) { "signature must be 64 bytes" }
        val finalSignatures = signatures.toMutableList()
        finalSignatures[signerIndex] = signature
        return SolanaTransactionCodec.serializeTransaction(finalSignatures, message)
    }

    companion object {
        const val SIGNATURE_LENGTH = 64
    }
}

fun interface SolanaExactTransactionBuilder {
    fun buildUnsignedTransaction(request: SolanaExactPaymentRequest): UnsignedSolanaTransaction
}

fun interface SolanaTransactionSigner {
    fun signMessage(message: ByteArray): ByteArray
}

data class ExactPaymentPayload(
    val x402Version: Int,
    val accepted: JsonObject,
    val transaction: String,
    val resource: ResourceInfo?,
)

class ExactPaymentClient(
    private val transactionBuilder: SolanaExactTransactionBuilder,
    private val signer: SolanaTransactionSigner,
) {
    fun createPaymentHeaders(
        selected: SelectedChallenge,
        payer: String,
        x402Version: Int = 2,
    ): Map<String, String> =
        mapOf(PAYMENT_SIGNATURE_HEADER to createPaymentHeaderValue(selected, payer, x402Version))

    fun createPaymentHeaderValue(
        selected: SelectedChallenge,
        payer: String,
        x402Version: Int = 2,
    ): String {
        val payload = createPaymentPayload(selected, payer, x402Version)
        val envelope = JsonObject().apply {
            addProperty("x402Version", payload.x402Version)
            add("accepted", payload.accepted)
            payload.resource?.let { add("resource", it.toJsonObject()) }
            add(
                "payload",
                JsonObject().apply {
                    addProperty("transaction", payload.transaction)
                },
            )
        }

        return Base64.getEncoder().encodeToString(gson.toJson(envelope).toByteArray(Charsets.UTF_8))
    }

    fun createPaymentPayload(
        selected: SelectedChallenge,
        payer: String,
        x402Version: Int = 2,
    ): ExactPaymentPayload {
        require(x402Version == 2) { "Only x402Version 2 is supported by the Kotlin exact scaffold" }
        require(payer.isNotBlank()) { "payer is required for SVM exact payment requests" }

        val request = selected.toRequest(payer)
        val unsignedTransaction = transactionBuilder.buildUnsignedTransaction(request)

        val signedTransaction = unsignedTransaction.signedWith(signer.signMessage(unsignedTransaction.message))

        return ExactPaymentPayload(
            x402Version = x402Version,
            accepted = request.accepted,
            transaction = Base64.getEncoder().encodeToString(signedTransaction),
            resource = selected.resource,
        )
    }

    private fun SelectedChallenge.toRequest(payer: String): SolanaExactPaymentRequest {
        val requirement = requirement
        require(requirement.scheme == "exact") { "Only exact payment requirements are supported" }
        require(requirement.network.startsWith("solana:")) {
            "Only Solana CAIP-2 exact payment requirements are supported"
        }
        require(requirement.asset.isNotBlank()) { "asset is required for SVM exact payment requirements" }
        require(requirement.amount.toULongOrNull() != null) {
            "amount must be an unsigned integer string"
        }

        val payTo = requirement.payTo?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("payTo is required for SVM exact payment requirements")
        // Fail-fast on a self-transfer challenge: when payTo equals the payer wallet
        // the SPL Token program rejects the transfer on-chain (source and destination
        // ATAs are identical). Catch this on the client before any Base58 decoding,
        // ATA derivation, or RPC work happens.
        require(payTo != payer) { "payTo must differ from payer (self-transfer)" }
        // Managed fee payer is optional. Rust spine
        // (rust/crates/x402/src/client/exact/payment.rs) treats
        // `requirements.fee_payer_key` as optional and falls back to the
        // signer (`payer`) as the actual transaction fee payer when absent.
        // When present, it must be operationally distinct from the transfer
        // authority and the recipient — otherwise a malicious server
        // challenge could either drain the user's wallet via fee
        // attribution or create a self-pay loop.
        val feePayer = requirement.extra.string("feePayer")
        if (feePayer != null) {
            require(feePayer != payer) {
                "managed fee payer must differ from the transfer authority (payer)"
            }
            require(payTo != feePayer) { "payTo must differ from the managed fee payer" }
        }
        // Reject server-supplied tokenProgram values that are not on the
        // canonical SPL allowlist (classic SPL Token or Token-2022). Otherwise
        // a malicious server can set extra.tokenProgram to an arbitrary
        // executable program ID and have the user sign a transferChecked
        // instruction routed through that program. Validate before any
        // transaction-building, RPC or signing work happens.
        requirement.extra.string("tokenProgram")?.let { requireAllowedTokenProgram(it) }
        val memo = requirement.extra.string("memo")
        if (memo != null && memo.toByteArray(Charsets.UTF_8).size > MAX_MEMO_BYTES) {
            throw IllegalArgumentException("extra.memo exceeds maximum $MAX_MEMO_BYTES bytes")
        }

        return SolanaExactPaymentRequest(
            payer = payer,
            network = requirement.network,
            asset = requirement.asset,
            amount = requirement.amount,
            payTo = payTo,
            feePayer = feePayer,
            memo = memo,
            maxTimeoutSeconds = requirement.maxTimeoutSeconds,
            accepted = requirement.toAcceptedJson(),
        )
    }

    private fun PaymentRequirement.toAcceptedJson(): JsonObject {
        // Canonical v2 accepted shape. Mirrors rust spine
        // `PaymentRequirements::to_accepted_value` at
        // rust/crates/x402/src/protocol/schemes/exact/types.rs so the
        // credential's `accepted` round-trips identically when the rust
        // server re-serialises both sides via the same Serialize impl
        // inside `find_matching_requirement`. Echoing the raw offered
        // object verbatim would leak deprecated aliases (`maxAmountRequired`,
        // `currency`, `recipient`) into the credential and cause the
        // structural-equality match to fail even though the underlying
        // values agree.
        val accepted = raw.deepCopy()
        // Strip deprecated wire aliases that we have already promoted to
        // canonical field names on the typed `PaymentRequirement`.
        accepted.remove("maxAmountRequired")
        accepted.remove("currency")
        accepted.remove("recipient")
        accepted.addProperty("scheme", scheme)
        accepted.addProperty("network", network)
        accepted.addProperty("asset", asset)
        accepted.addProperty("amount", amount)
        payTo?.let { accepted.addProperty("payTo", it) }
        maxTimeoutSeconds?.let { accepted.addProperty("maxTimeoutSeconds", it) }
        if (!accepted.has("extra")) {
            accepted.add(
                "extra",
                JsonObject().apply {
                    extra.forEach { (key, value) -> add(key, value.deepCopy()) }
                },
            )
        }
        return accepted
    }

    private fun ResourceInfo.toJsonObject(): JsonObject {
        val obj = raw.deepCopy()
        url?.let { obj.addProperty("url", it) }
        description?.let { obj.addProperty("description", it) }
        mimeType?.let { obj.addProperty("mimeType", it) }
        return obj
    }

    private fun Map<String, JsonElement>.string(name: String): String? =
        get(name)
            ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
            ?.asString
            ?.takeIf { it.isNotBlank() }

    private companion object {
        val gson = Gson()
    }
}
