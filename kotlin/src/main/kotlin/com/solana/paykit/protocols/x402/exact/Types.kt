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
)

/**
 * Effective recipient: prefers ``recipient``, falls back to ``payTo``.
 *
 * ``recipient ?: payTo`` — the rust spine deserializes the destination as
 * ``recipient.or_else(payTo)`` (types.rs:334-336), so a conflicting top-level
 * ``recipient`` field WINS over ``payTo``. Matching this keeps Kotlin and the
 * canonical verifier selecting the same recipient on the same wire.
 */
val X402AcceptsEntry.effectivePayTo: String? get() = recipient ?: payTo

/**
 * Effective mint: top-level ``currency`` wins; ``asset`` is the fallback.
 *
 * ``currency ?: asset`` — the rust spine deserializes the mint as
 * ``currency.or_else(asset)`` (types.rs:340-342), so a conflicting top-level
 * ``currency`` field WINS over ``asset``. Matching this keeps Kotlin and the
 * canonical verifier selecting the same mint on the same wire.
 */
val X402AcceptsEntry.effectiveAsset: String? get() = currency ?: asset

/**
 * Effective token program: prefers the TOP-LEVEL ``tokenProgram``, then
 * the ``extra.tokenProgram`` nested alias. Top-level-first matches the
 * rust spine, which normalizes the canonical token program onto the
 * top-level field.
 */
val X402AcceptsEntry.effectiveTokenProgram: String? get() = tokenProgram ?: extra?.tokenProgram

/**
 * Effective token decimals: prefers the TOP-LEVEL ``decimals``, then the
 * ``extra.decimals`` nested alias. Top-level-first matches the rust spine.
 */
val X402AcceptsEntry.effectiveDecimals: Int? get() = decimals ?: extra?.decimals

/**
 * Effective pinned blockhash: prefers the TOP-LEVEL ``recentBlockhash``,
 * then the ``extra.recentBlockhash`` nested alias. Top-level-first matches
 * the rust spine.
 */
val X402AcceptsEntry.effectiveRecentBlockhash: String? get() = recentBlockhash ?: extra?.recentBlockhash

/**
 * Effective managed fee payer pubkey, or ``null`` when the offer does not
 * request a managed fee payer.
 *
 * Mirrors the rust spine ``build_payment``: a managed fee payer is used when
 * the ``feePayer`` toggle is true AND a ``feePayerKey`` is present. The rust
 * parser also normalizes ``feePayer = true`` whenever ``feePayerKey`` is set,
 * so a top-level ``feePayerKey`` with no explicit ``feePayer`` flag still
 * selects the managed fee payer. The top-level fields take precedence; the
 * nested ``extra.feePayer`` (a bare pubkey string) is read as a fallback so
 * the older nested-only offer shape keeps working.
 */
val X402AcceptsEntry.effectiveFeePayerKey: String? get() {
    // Mirror the rust normalization (types.rs): the managed fee-payer key is the
    // top-level feePayerKey, else the nested extra.feePayer alias. The feePayer
    // boolean toggle then gates BOTH sources: it defaults to true when a key is
    // present and only an explicit `false` opts out. The prior code applied the
    // toggle only to the top-level key and returned extra.feePayer
    // unconditionally, so an offer with extra.feePayer + feePayer=false wrongly
    // selected a managed fee payer.
    val key = feePayerKey ?: extra?.feePayer
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
