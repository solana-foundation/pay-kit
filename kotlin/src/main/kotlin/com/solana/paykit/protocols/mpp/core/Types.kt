package com.solana.paykit.protocols.mpp.core

import com.solana.paykit.paycore.*

import kotlinx.serialization.Serializable
import java.time.Instant
import java.time.OffsetDateTime
import java.time.format.DateTimeParseException

// MppException lives in paycore (crypto primitives need it, and protocols need
// crypto) and is brought into scope by the wildcard import above. No same-package
// typealias here: aliasing a sealed class within its own consuming package
// shadows the import and breaks resolution of its nested members.

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

    /**
     * Returns true if this challenge has an `expires` timestamp that is at or
     * before [now] (audit #10). A challenge with no `expires` is never expired
     * (the spec allows omitting it). FAIL-CLOSED: an `expires` value that is
     * present but does not parse as an RFC3339 / ISO-8601 offset timestamp is
     * treated as expired, so a malformed timestamp cannot bypass the refusal.
     */
    fun isExpired(now: Instant = Instant.now()): Boolean {
        val raw = expires ?: return false
        val expiresAt = try {
            OffsetDateTime.parse(raw).toInstant()
        } catch (_: DateTimeParseException) {
            return true
        }
        return !expiresAt.isAfter(now)
    }

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

/**
 * Solana charge request payload encoded in the challenge `request` field.
 *
 * `recipient` and `methodDetails` are optional on the wire, matching the rust
 * spine `ChargeRequest` (charge.rs:27-40, both `Option<...>` with
 * `skip_serializing_if = "Option::is_none"`). The client defaults a missing
 * `methodDetails` (rust `unwrap_or_default`, charge.rs:203-209) and only
 * errors on a missing `recipient` when it is actually needed to build the
 * transaction (rust charge.rs:211-214). Requiring both at deserialization
 * would reject challenges the rust client decodes.
 */
@Serializable
data class ChargeRequest(
    val amount: String,
    val currency: String,
    val recipient: String? = null,
    val description: String? = null,
    val externalId: String? = null,
    val methodDetails: SolanaChargeMethodDetails? = null,
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
