package com.solana.paykit.protocols.x402.exact

import kotlinx.serialization.Serializable

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
    val maxTimeoutSeconds: Int? = null,
    val extra: X402Extra? = null,
)

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
