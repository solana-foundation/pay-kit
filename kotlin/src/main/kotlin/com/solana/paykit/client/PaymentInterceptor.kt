package com.solana.paykit.client

import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody

/**
 * The credential a payment interceptor produced for a 402 challenge.
 *
 * [headerName]/[headerValue] are attached to the replayed request (e.g.
 * ``Authorization: Payment ...`` for MPP, ``Payment-Signature: ...`` for
 * x402). [settlementHeader] names the response header carrying the on-chain
 * settlement reference so the call surface can surface it.
 */
internal data class PaymentCredentialHeader(
    val headerName: String,
    val headerValue: String,
    val settlementHeader: String,
)

/**
 * OkHttp [Interceptor] that turns a 402 into a paid retry.
 *
 * This is the idiomatic home for the pay-kit retry loop: cross-cutting
 * payment handling lives in one OkHttp interceptor, exactly how Retrofit and
 * OkHttp model auth + retry (``Authenticator`` / interceptor). One concrete
 * interceptor exists per protocol (charge, x402); each supplies the protocol's
 * challenge parse + credential build through [buildCredential].
 *
 * Behaviour, identical to the previous ad-hoc transports:
 *
 * 1. Proceed with the request. If the status is not 402, return it untouched.
 * 2. Buffer the 402 body so it stays re-readable, then ask [buildCredential]
 *    for a credential. A ``null`` credential (no supported challenge) hands
 *    the original 402 back to the caller with a fresh, re-readable body.
 * 3. Build/sign failures propagate (the caller can tell "no supported offer"
 *    apart from "payment construction failed").
 * 4. Replay the request once with the credential header attached.
 *
 * The retry is single-shot and 402-only: 5xx, network errors, and other 4xx
 * are never retried.
 */
internal abstract class PaymentInterceptor : Interceptor {

    /**
     * Parses the protocol challenge from the 402 [response]/[bodyText] and
     * builds a signed credential header, or returns ``null`` when no supported
     * challenge is advertised (the caller is handed the original 402).
     *
     * Implementations may throw to signal a build/sign failure on a challenge
     * that WAS supported; that exception propagates to the caller.
     */
    protected abstract fun buildCredential(
        response: Response,
        bodyText: String,
    ): PaymentCredentialHeader?

    final override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val initial = chain.proceed(request)
        if (initial.code != 402) {
            return initial
        }

        // Buffer the 402 body + headers before closing so the challenge parse
        // and the fall-back 402 both see a re-readable body (mirrors the go +
        // python clients which buffer and `return resp`).
        val contentType = initial.body?.contentType()
        val bodyBytes = initial.body?.bytes() ?: ByteArray(0)
        val bodyText = bodyBytes.decodeToString()

        fun buffered402(): Response = initial.newBuilder()
            .body(bodyBytes.toResponseBody(contentType))
            .build()

        val credential = buildCredential(buffered402(), bodyText)
            ?: return buffered402()

        // A supported challenge was selected; the 402 body is consumed and the
        // request replayed with the credential header. Tag the response so the
        // call surface knows a payment was attached and which settlement header
        // to read.
        initial.close()
        val paidRequest: Request = request.newBuilder()
            .header(credential.headerName, credential.headerValue)
            .build()
        return chain.proceed(paidRequest).newBuilder()
            .header(PAYMENT_SENT_HEADER, "true")
            .header(SETTLEMENT_HEADER_NAME, credential.settlementHeader)
            .header(PAYMENT_HEADER_VALUE, credential.headerValue)
            .build()
    }

    companion object {
        /**
         * Synthetic response header the interceptor stamps when it attached a
         * payment, read back by the call surface. Not sent over the wire (it is
         * added to the in-memory [Response] after the call returns).
         */
        const val PAYMENT_SENT_HEADER = "X-PayKit-Payment-Sent"

        /** Synthetic header naming the protocol's settlement header. */
        const val SETTLEMENT_HEADER_NAME = "X-PayKit-Settlement-Header"

        /** Synthetic header carrying the credential header value that was sent. */
        const val PAYMENT_HEADER_VALUE = "X-PayKit-Payment-Header"
    }
}
