package com.solana.mpp

import kotlinx.serialization.Serializable

sealed class MppException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {
    class InvalidBase64Url(cause: Throwable? = null) : MppException("invalid base64url value", cause)
    object InvalidHeader : MppException("invalid Payment header")
    class InvalidJson(cause: Throwable? = null) : MppException("invalid JSON payload", cause)
    object InvalidPaymentScheme : MppException("expected Payment scheme")
    class MissingField(field: String) : MppException("missing required field: $field")
    class UnsupportedChallenge(method: String, intent: String) :
        MppException("unsupported challenge: method=$method intent=$intent")
}

@Serializable
data class PaymentChallenge(
    val id: String,
    val realm: String,
    val method: String,
    val intent: String,
    val request: String,
    val expires: String? = null,
    val digest: String? = null,
    val opaque: String? = null,
) {
    fun chargeRequest(): ChargeRequest = MppHeaders.decodeChargeRequest(request)

    fun requireSolanaCharge() {
        if (method != "solana" || intent != "charge") {
            throw MppException.UnsupportedChallenge(method, intent)
        }
    }

    fun echo(): ChallengeEcho =
        ChallengeEcho(
            id = id,
            realm = realm,
            method = method,
            intent = intent,
            request = request,
            expires = expires,
            digest = digest,
            opaque = opaque,
        )
}

@Serializable
data class ChallengeEcho(
    val id: String,
    val realm: String,
    val method: String,
    val intent: String,
    val request: String,
    val expires: String? = null,
    val digest: String? = null,
    val opaque: String? = null,
)

@Serializable
data class ChargeRequest(
    val amount: String,
    val currency: String,
    val recipient: String,
    val externalId: String? = null,
    val methodDetails: SolanaChargeMethodDetails,
)

@Serializable
data class SolanaChargeMethodDetails(
    val network: String? = null,
    val decimals: Int? = null,
    val feePayer: Boolean? = null,
    val feePayerKey: String? = null,
    val recentBlockhash: String? = null,
    val splits: List<SolanaChargeSplit>? = null,
    val tokenProgram: String? = null,
)

@Serializable
data class SolanaChargeSplit(
    val recipient: String,
    val amount: String,
    val ataCreationRequired: Boolean? = null,
    val memo: String? = null,
)

@Serializable
data class PaymentCredential(
    val challenge: ChallengeEcho,
    val payload: CredentialPayload,
    val source: String? = null,
)

@Serializable
data class CredentialPayload(
    val type: String,
    val transaction: String? = null,
    val signature: String? = null,
) {
    companion object {
        fun transaction(transaction: String): CredentialPayload =
            CredentialPayload(type = "transaction", transaction = transaction)

        fun signature(signature: String): CredentialPayload =
            CredentialPayload(type = "signature", signature = signature)
    }
}
