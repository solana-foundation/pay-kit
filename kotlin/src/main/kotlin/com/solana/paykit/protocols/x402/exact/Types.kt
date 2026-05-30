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
    // The verbatim offered object as received on the wire, kept so the client
    // can echo it back unchanged in the `Payment-Signature` envelope's
    // `accepted` field. The rust verifier structurally compares the echoed
    // `accepted` against its offered options, so server-specific fields the
    // typed properties above do not model must survive the round trip.
    // `null` for entries built in code (those re-serialize from the typed
    // fields). Excluded from (de)serialization; populated during parsing.
    @Transient val raw: JsonElement? = null,
)

/** Effective recipient: prefers ``payTo``, falls back to ``recipient``. */
val X402AcceptsEntry.effectivePayTo: String? get() = payTo ?: recipient

/**
 * Effective mint: prefers the top-level ``asset``, falls back to ``currency``.
 *
 * Precedence is TOP-LEVEL FIRST to match the rust spine normalization
 * (``effective_asset = asset.or(currency)`` /
 * ``effectiveAsset = currency ?: asset`` in the audit direction: the
 * rust-normalized requirement carries the canonical value at the top
 * level, so the top-level field wins over any aliased fallback).
 */
val X402AcceptsEntry.effectiveAsset: String? get() = asset ?: currency

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
