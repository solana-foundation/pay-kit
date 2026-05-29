package com.solana.paykit.paycore

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
