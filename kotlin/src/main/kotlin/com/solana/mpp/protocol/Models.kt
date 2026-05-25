package com.solana.mpp.protocol

import com.solana.mpp.crypto.*

import kotlinx.serialization.Serializable

/** Base exception hierarchy for Kotlin MPP SDK failures. */
sealed class MppException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {
    class InvalidBase64Url(cause: Throwable? = null) : MppException("invalid base64url value", cause)
    class InvalidBase58(character: Char) : MppException("invalid base58 character: '$character'")
    object InvalidHeader : MppException("invalid Payment header")
    class InvalidJson(cause: Throwable? = null) :
        MppException("invalid JSON payload: ${cause?.message ?: "<no detail>"}", cause)
    object InvalidPaymentScheme : MppException("expected Payment scheme")
    class MissingField(field: String) : MppException("missing required field: $field")
    class MemoTooLong(size: Int) : MppException("memo cannot exceed 566 bytes (got $size)")
    class InvalidPublicKey(value: String) : MppException("invalid Solana public key: '$value'")
    class InvalidTransaction(message: String) : MppException(message)
    class UnsupportedChallenge(method: String, intent: String) :
        MppException("unsupported challenge: method=$method intent=$intent")
}

/** Parsed MPP `WWW-Authenticate` challenge. */
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
    /** Decodes this challenge's request as a Solana charge request. */
    fun chargeRequest(): ChargeRequest = MppHeaders.decodeChargeRequest(request)

    /** Fails unless this challenge targets the Solana charge intent. */
    fun requireSolanaCharge() {
        if (method != "solana" || intent != "charge") {
            throw MppException.UnsupportedChallenge(method, intent)
        }
    }

    /** Creates the challenge echo included in an MPP credential. */
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

/** Challenge fields echoed inside a client credential. */
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

/** Solana charge request payload encoded in the challenge `request` field. */
@Serializable
data class ChargeRequest(
    val amount: String,
    val currency: String,
    val recipient: String,
    val description: String? = null,
    val externalId: String? = null,
    val methodDetails: SolanaChargeMethodDetails,
)

/** Solana-specific method details for a charge request. */
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

/** Split transfer target for a Solana charge request. */
@Serializable
data class SolanaChargeSplit(
    val recipient: String,
    val amount: String,
    val ataCreationRequired: Boolean? = null,
    val memo: String? = null,
    val label: String? = null,
)

/** MPP credential submitted in the `Authorization` header. */
@Serializable
data class PaymentCredential(
    val challenge: ChallengeEcho,
    val payload: CredentialPayload,
    val source: String? = null,
)

/** Credential payload carrying either a signed transaction or signature. */
@Serializable
data class CredentialPayload(
    val type: String,
    val transaction: String? = null,
    val signature: String? = null,
) {
    companion object {
        /** Creates a transaction credential payload. */
        fun transaction(transaction: String): CredentialPayload =
            CredentialPayload(type = "transaction", transaction = transaction)

        /** Creates a signature credential payload. */
        fun signature(signature: String): CredentialPayload =
            CredentialPayload(type = "signature", signature = signature)
    }
}
