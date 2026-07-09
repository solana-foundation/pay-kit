package com.solana.paykit.protocols.x402.client.upto

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.PaymentChannels
import com.solana.paykit.paycore.Programs
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.paycore.SolanaSigner
import com.solana.paykit.protocols.x402.X402_VERSION
import com.solana.paykit.protocols.x402.upto.UPTO_SCHEME
import com.solana.paykit.protocols.x402.upto.UptoPayload
import com.solana.paykit.protocols.x402.upto.UptoRequirements
import com.solana.paykit.protocols.x402.upto.UptoSignatureEnvelope

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Base64

/**
 * x402 ``upto`` client (payment-channel asset transfer method): challenge
 * parsing and authorization building.
 *
 * The client opens a channel whose deposit is the authorized maximum, with the
 * advertised receiver authorizer as payee/authorized signer and the advertised
 * fee payer as transaction/rent payer. The client signs only its payer slot of
 * the ``open`` transaction; the server co-signs the fee-payer slot and
 * broadcasts. The
 * client never signs a voucher and never needs SOL.
 *
 * The envelope is the canonical x402 v2 shape ``{ x402Version, accepted,
 * payload }``: scheme and network live inside ``accepted``, not at the envelope
 * level. It is encoded as compact JSON then standard base64 (with padding) and
 * carried in the ``Payment-Signature`` header.
 */

/** Header carrying the 402 challenge. */
private const val PAYMENT_REQUIRED_HEADER = "payment-required"

private val json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = false
    explicitNulls = false
}

// ── Challenge parsing ─────────────────────────────────────────────────────────

/**
 * Parses a 402 ``upto`` challenge from response headers and/or body, returning
 * the first advertised ``upto`` requirement, or ``null`` when none is present.
 *
 * Use [parseUptoAccepts] to consider every advertised currency.
 */
fun parseUptoChallenge(headers: Map<String, String>, body: String? = null): UptoRequirements? =
    parseUptoAccepts(headers, body).firstOrNull()

/**
 * Parses every ``upto`` requirement advertised on a 402 (each ``accepts[]``
 * entry whose ``scheme`` is ``upto``), so a balance- and cost-aware selector can
 * choose among the offered currencies. Empty when none are present.
 *
 * Decodes the standard-base64 JSON ``payment-required`` header first (case
 * insensitive), then falls back to a JSON body. Each returned requirement
 * carries its verbatim wire object in [UptoRequirements.raw] so it can be echoed
 * back unchanged.
 */
fun parseUptoAccepts(headers: Map<String, String>, body: String? = null): List<UptoRequirements> {
    val fromHeader = lookupHeader(headers, PAYMENT_REQUIRED_HEADER)?.let { headerValue ->
        val decoded = try {
            Base64.getDecoder().decode(headerValue).decodeToString()
        } catch (_: Exception) {
            null
        }
        decoded?.let { acceptsFrom(it) }
    }
    // The header wins only when it decodes to a parseable envelope; a header
    // that is absent, not base64, or not a valid envelope falls through to the
    // body, mirroring the rust spine's `from_header.or_else(body)` chain. A
    // header that parses to an envelope with no upto offers does NOT fall back.
    return fromHeader ?: body?.let { acceptsFrom(it) } ?: emptyList()
}

private fun lookupHeader(headers: Map<String, String>, name: String): String? {
    val target = name.lowercase()
    return headers.entries.firstOrNull { it.key.lowercase() == target }?.value
}

/**
 * Parses an envelope from one source (decoded header text or body), returning
 * its ``upto`` accepts (possibly empty), or ``null`` when the text is not a
 * parseable envelope so the caller can fall back to the next source.
 */
private fun acceptsFrom(text: String): List<UptoRequirements>? {
    return try {
        val obj = json.parseToJsonElement(text).jsonObject
        // A parseable envelope must carry x402Version (the rust spine requires it).
        // `accepts` is optional there (serde default), so an envelope that omits it
        // resolves to no offers rather than falling through to the next source.
        when {
            obj["x402Version"] == null -> null
            else -> when (val accepts = obj["accepts"]?.jsonArray) {
                null -> emptyList()
                else -> accepts.mapNotNull { element ->
                    val scheme = element.jsonObject["scheme"]?.jsonPrimitive?.content
                    if (scheme != UPTO_SCHEME) {
                        null
                    } else {
                        json.decodeFromJsonElement(UptoRequirements.serializer(), element).copy(raw = element)
                    }
                }
            }
        }
    } catch (_: Exception) {
        null
    }
}

// ── Payment building ──────────────────────────────────────────────────────────

/**
 * Builds an ``upto`` payload for a payment-channel requirement.
 *
 * [expiresAt] is the voucher/authorization deadline (Unix seconds); [nonce] is
 * kept for source compatibility but ignored because the payload nonce is the
 * channel salt decimal string. [saltProvider] mints the channel salt (default:
 * a random u64); it is injectable so deterministic tests can pin it. The
 * requirement MUST carry ``extra.recentBlockhash`` and
 * ``extra.recentSlot`` (the server prefetches both into the 402 challenge);
 * ``recentSlot`` becomes the program's ``open_slot`` channel PDA seed and the
 * program rejects future slots and slots older than the 1500-slot open window.
 */
fun buildUptoPayload(
    signer: SolanaSigner,
    requirements: UptoRequirements,
    expiresAt: Long,
    nonce: String? = null,
    saltProvider: () -> ULong = PaymentChannels::uniqueSalt,
): UptoPayload {
    val extra = requirements.extra

    val max = requirements.amount.toULongOrNull()
        ?: throw IllegalArgumentException("x402 client: invalid upto amount: ${requirements.amount}")

    val mint = parsePubkey(requirements.asset, "asset mint")

    val feePayerStr = extra.feePayer
        ?: throw IllegalArgumentException("x402 client: requirement missing extra.feePayer")
    val feePayer = parsePubkey(feePayerStr, "feePayer")
    val receiverAuthorizerStr = extra.receiverAuthorizer
        ?: throw IllegalArgumentException("x402 client: requirement missing extra.receiverAuthorizer")
    val receiverAuthorizer = parsePubkey(receiverAuthorizerStr, "receiverAuthorizer")
    if (extra.withdrawDelay <= 0) {
        throw IllegalArgumentException("x402 client: requirement missing extra.withdrawDelay")
    }
    val beneficiary = parsePubkey(requirements.payTo, "payTo")

    val recipients = if (beneficiary == receiverAuthorizer) {
        emptyList()
    } else {
        listOf(PaymentChannels.Distribution(recipient = beneficiary, bps = 10_000))
    }

    val programId = PublicKey.fromBase58(PaymentChannels.PROGRAM_ID)
    val tokenProgram = extra.tokenProgram?.let { parsePubkey(it, "tokenProgram") }
        ?: PublicKey.fromBase58(Programs.TOKEN_PROGRAM)

    val blockhashStr = extra.recentBlockhash
        ?: throw IllegalArgumentException("x402 client: requirement missing extra.recentBlockhash")
    val blockhash = Base58.decode(blockhashStr)

    val openSlot = extra.recentSlot
        ?: throw IllegalArgumentException("x402 client: requirement missing extra.recentSlot")

    // The channel salt is also the payload nonce, encoded as decimal.
    val salt = saltProvider()
    val open = PaymentChannels.buildOpenTransaction(
        payer = signer,
        payee = receiverAuthorizer,
        mint = mint,
        authorizedSigner = receiverAuthorizer,
        salt = salt,
        deposit = max,
        gracePeriod = extra.withdrawDelay.toUInt(),
        openSlot = openSlot,
        recipients = recipients,
        tokenProgram = tokenProgram,
        programId = programId,
        feePayer = feePayer,
        recentBlockhash = blockhash,
    )

    return UptoPayload(
        from = signer.address,
        maxAmount = max.toString(),
        expiresAt = expiresAt,
        validAfter = extra.validAfter ?: 0L,
        nonce = salt.toString(),
        channelId = open.channelId.toBase58(),
        deposit = max.toString(),
        authorizedSigner = receiverAuthorizerStr,
        openSlot = openSlot.toString(),
        openTransaction = open.transaction,
    )
}

/**
 * Wraps a payload in a ``Payment-Signature`` envelope and standard-base64
 * encodes it (with padding, NOT base64url).
 *
 * The ``accepted`` field echoes the requirement's verbatim wire object when it
 * was parsed off the wire ([UptoRequirements.raw]); otherwise it re-serializes
 * the typed requirement.
 */
fun encodeUptoHeader(requirements: UptoRequirements, payload: UptoPayload): String {
    val acceptedJson = requirements.raw
        ?: json.encodeToJsonElement(UptoRequirements.serializer(), requirements)
    val envelope = UptoSignatureEnvelope(
        x402Version = X402_VERSION,
        accepted = acceptedJson,
        payload = payload,
    )
    val text = json.encodeToString(UptoSignatureEnvelope.serializer(), envelope)
    return Base64.getEncoder().encodeToString(text.encodeToByteArray())
}

/**
 * Builds the full ``Payment-Signature`` header value for an ``upto`` payment:
 * [buildUptoPayload] wrapped by [encodeUptoHeader].
 */
fun buildUptoHeader(
    signer: SolanaSigner,
    requirements: UptoRequirements,
    expiresAt: Long,
    nonce: String? = null,
): String {
    val payload = buildUptoPayload(signer, requirements, expiresAt, nonce)
    return encodeUptoHeader(requirements, payload)
}

private fun parsePubkey(value: String, label: String): PublicKey =
    try {
        PublicKey.fromBase58(value)
    } catch (error: Exception) {
        throw IllegalArgumentException("x402 client: invalid $label: $value")
    }
