package com.solana.paykit.client

import okhttp3.Response

/**
 * A protocol-agnostic result for a pay-kit call.
 *
 * Carries the final OkHttp [response] plus whether a payment was attached and,
 * when the server returned a settlement reference (the on-chain signature for
 * MPP, the x402 ``Payment-Response`` echo), that value. Mirrors the swift
 * ``PayKit`` result shape so the two clients read the same across languages.
 *
 * Callers own the response body and MUST close it (use [use] or
 * `result.response.close()`).
 */
data class PayResponse(
    /** The final OkHttp response after any payment retry. */
    val response: Response,
    /** True when the client attached a payment credential and replayed. */
    val paymentSent: Boolean,
    /**
     * The credential header value the client sent on the paid retry, when a
     * payment was made (the ``Authorization: Payment ...`` value for MPP, the
     * ``Payment-Signature`` value for x402). ``null`` when no payment was made.
     * Surfaced so interop adapters can echo the exact sent credential.
     */
    val paymentHeader: String?,
    /**
     * The on-chain settlement reference the server reported, when present.
     *
     * For MPP this is the ``Payment-Receipt`` header; for x402 the
     * ``Payment-Response`` header. ``null`` when no payment was made or the
     * server did not echo a settlement.
     */
    val settlement: String?,
) {
    /** HTTP status code of the final response. */
    val status: Int get() = response.code

    /**
     * Runs [block] with the response body string and closes the response.
     *
     * Convenience decode helper for the common "read the unlocked body once"
     * case. The response is closed when [block] returns.
     */
    inline fun <T> use(block: (body: String?) -> T): T =
        response.use { block(it.body?.string()) }
}
