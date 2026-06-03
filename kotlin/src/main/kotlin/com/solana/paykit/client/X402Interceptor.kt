package com.solana.paykit.client

import com.solana.paykit.paycore.SolanaSigner
import com.solana.paykit.protocols.x402.client.exact.ChallengeSelection
import com.solana.paykit.protocols.x402.client.exact.buildPaymentHeader
import com.solana.paykit.protocols.x402.client.exact.parseX402Challenge
import okhttp3.Response

/**
 * [PaymentInterceptor] for the x402 ``exact`` protocol.
 *
 * On a 402 it parses the ``payment-required`` header (or ``accepts[]`` body),
 * selects an offer per [selection], builds and signs the v0 payment
 * transaction, and replays with the ``Payment-Signature`` header. Settlement
 * is reported in the ``Payment-Response`` response header.
 *
 * A 402 with no supported x402 offer yields ``null`` (the caller is handed the
 * original 402), matching the rust/go/python clients. Build/sign failures on a
 * matched offer propagate.
 */
internal class X402Interceptor(
    private val signer: SolanaSigner,
    private val rpcBlockhashProvider: () -> ByteArray,
    private val selection: ChallengeSelection,
) : PaymentInterceptor() {

    override fun buildCredential(response: Response, bodyText: String): PaymentCredentialHeader? {
        val headers = buildMap {
            for (name in response.headers.names()) {
                // Join multi-values with ", " per RFC 7230.
                put(name.lowercase(), response.headers.values(name).joinToString(", "))
            }
        }
        val requirement = parseX402Challenge(headers, bodyText, selection)
            ?: return null
        val paymentHeader = buildPaymentHeader(signer, requirement, rpcBlockhashProvider)
        return PaymentCredentialHeader(
            headerName = PAYMENT_SIGNATURE_HEADER,
            headerValue = paymentHeader,
            settlementHeader = PAYMENT_RESPONSE_HEADER,
        )
    }

    companion object {
        const val PAYMENT_SIGNATURE_HEADER = "Payment-Signature"
        const val PAYMENT_RESPONSE_HEADER = "Payment-Response"
    }
}
