package com.solana.paykit.protocols.x402.exact

import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonElement

/**
 * x402 ``exact`` wire shapes for Kotlin.
 *
 * Mirrors the Python precedent at
 * ``python/src/pay_kit/protocols/x402/exact/types.py`` and the rust spine
 * at ``rust/crates/x402/src/client/exact/payment.rs``.
 */

/** The ``extra`` block stamped by the pay_kit x402 server onto an accept offer. */
@Serializable
data class X402Extra(
    val feePayer: String? = null,
    val decimals: Int? = null,
    val tokenProgram: String? = null,
    val memo: String? = null,
    val recentBlockhash: String? = null,
)

/** One x402 ``accepts[]`` offer entry (the server requirement). */
@Serializable
data class X402AcceptsEntry(
    val protocol: String? = null,
    val scheme: String? = null,
    val network: String? = null,
    val asset: String? = null,
    val amount: String? = null,
    val maxAmountRequired: String? = null,
    val payTo: String? = null,
    // Recipient alias emitted by the rust-normalized requirement shape (the
    // wire field is `payTo`; `recipient` is read as a fallback).
    val recipient: String? = null,
    val maxTimeoutSeconds: Int? = null,
    val extra: X402Extra? = null,
    // Top-level currency fields. Some x402 servers carry the mint as
    // ``currency`` with ``decimals`` / ``tokenProgram`` / ``recentBlockhash``
    // at the top level instead of nested under ``asset`` + ``extra``. Read as
    // fallbacks so the client can pay a server emitting either shape.
    val currency: String? = null,
    val decimals: Int? = null,
    val tokenProgram: String? = null,
    val recentBlockhash: String? = null,
    // Top-level managed-fee-payer offer shape. The rust spine parses a
    // top-level ``feePayerKey`` (the facilitator pubkey that cosigns the
    // transaction server-side) and a ``feePayer`` boolean toggle; the
    // canonical normalization also derives ``feePayer = true`` whenever
    // ``feePayerKey`` is present. Read both at the top level so the client
    // honors this shape, not only the nested ``extra.feePayer`` alias.
    val feePayer: Boolean? = null,
    val feePayerKey: String? = null,
    // The verbatim offered object as received on the wire, kept so the client
    // can echo it back unchanged in the `Payment-Signature` envelope's
    // `accepted` field. The rust verifier structurally compares the echoed
    // `accepted` against its offered options, so server-specific fields the
    // typed properties above do not model must survive the round trip.
    // `null` for entries built in code (those re-serialize from the typed
    // fields). Excluded from (de)serialization; populated during parsing.
    @Transient val raw: JsonElement? = null,
    // The challenge's `resource` (PaymentRequired.resource), echoed in the
    // v2 envelope so the credential names the resource it pays for (servers
    // that bind payments to their route require it). `null` for entries
    // built in code. Excluded from (de)serialization; populated during parsing.
    @Transient val resource: JsonElement? = null,
)

// RULINGS X1: each term is read from its x402 field only. ``amount`` falls
// back to the v1 ``maxAmountRequired`` a legacy offer uses; the fields a server
// adds beside them (``recipient``, ``currency``, top-level ``tokenProgram``,
// ``decimals``, ``recentBlockhash``, ``feePayerKey``) are ignored, so the
// signed transfer pays what the echoed ``accepted`` object names.

/** Recipient: ``payTo``. */
val X402AcceptsEntry.effectivePayTo: String? get() = payTo

/** Mint: ``asset``. */
val X402AcceptsEntry.effectiveAsset: String? get() = asset

/** Token program hint: ``extra.tokenProgram``. */
val X402AcceptsEntry.effectiveTokenProgram: String? get() = extra?.tokenProgram

/** Token decimals hint: ``extra.decimals``. */
val X402AcceptsEntry.effectiveDecimals: Int? get() = extra?.decimals

/** Pinned blockhash: ``extra.recentBlockhash``. */
val X402AcceptsEntry.effectiveRecentBlockhash: String? get() = extra?.recentBlockhash

/**
 * Effective managed fee payer pubkey, or ``null`` when the offer does not
 * request a managed fee payer.
 *
 * The key is ``extra.feePayer``. The ``feePayer`` boolean toggle then gates
 * it: it defaults to true when a key is present and only an explicit
 * ``false`` opts out.
 */
val X402AcceptsEntry.effectiveFeePayerKey: String? get() {
    val key = extra?.feePayer
    if (key != null) {
        return if (feePayer != false) key else null
    }
    return null
}

/** The base64-decoded challenge body (``payment-required`` header or 402 body). */
@Serializable
data class X402Challenge(
    val x402Version: Int? = null,
    val accepts: List<X402AcceptsEntry> = emptyList(),
)

/** The ``payload`` block inside an x402 envelope. */
@Serializable
data class X402PayloadField(
    val transaction: String? = null,
)

/** An x402 envelope sent as the ``Payment-Signature`` header value (base64 JSON). */
@Serializable
data class X402Envelope(
    val x402Version: Int,
    val accepted: X402AcceptsEntry,
    val payload: X402PayloadField,
)
