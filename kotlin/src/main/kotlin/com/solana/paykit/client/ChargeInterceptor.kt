package com.solana.paykit.client

import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.SolanaSigner
import com.solana.paykit.protocols.mpp.client.BlockhashProvider
import com.solana.paykit.protocols.mpp.client.Charge
import com.solana.paykit.protocols.mpp.client.ChargePolicy
import com.solana.paykit.protocols.mpp.client.MintOwnerResolver
import com.solana.paykit.protocols.mpp.core.MppHeaders
import okhttp3.Response

/**
 * [PaymentInterceptor] for the MPP charge protocol.
 *
 * On a 402 it reads every advertised ``WWW-Authenticate`` challenge, selects
 * the Solana charge one, builds and signs the charge transaction, and replays
 * with ``Authorization: Payment ...``. Settlement is reported in the
 * ``Payment-Receipt`` response header.
 *
 * A 402 with no advertised challenge, or none targeting the Solana charge
 * scheme, throws [MppException.InvalidPaymentScheme] (the MPP charge contract:
 * a 402 here is a server protocol error, not an offer the client can decline).
 *
 * Because this is the auto-pay path — the user's wallet signs without a human
 * reviewing the challenge — the [ChargePolicy] is enforced here (audit #10,
 * #26): the always-on expired-challenge refusal in [Charge.buildCredentialHeader]
 * always applies, and [policy] binds the opt-in max-amount, expected-network,
 * and unknown-Token-2022 gates a caller configures.
 */
internal class ChargeInterceptor(
    private val signer: SolanaSigner,
    private val blockhashProvider: BlockhashProvider,
    private val computeUnitLimit: Int,
    private val computeUnitPrice: Long,
    private val mintOwnerResolver: MintOwnerResolver?,
    private val policy: ChargePolicy = ChargePolicy.NONE,
) : PaymentInterceptor() {

    override fun buildCredential(response: Response, bodyText: String): PaymentCredentialHeader? {
        val advertised = response.headers(WWW_AUTHENTICATE_HEADER)
        if (advertised.isEmpty()) {
            throw MppException.InvalidPaymentScheme
        }
        val challenge = MppHeaders.selectSolanaChargeChallenge(advertised)
            ?: throw MppException.InvalidPaymentScheme
        // Reuse the BlockhashProvider as the MintOwnerResolver when it
        // implements both (JsonRpcClient does), so the common single-RPC setup
        // resolves arbitrary-mint challenges without extra wiring.
        val resolver = mintOwnerResolver ?: (blockhashProvider as? MintOwnerResolver)
        val authorization = Charge.buildCredentialHeader(
            signer = signer,
            challenge = challenge,
            blockhashProvider = blockhashProvider,
            computeUnitLimit = computeUnitLimit,
            computeUnitPrice = computeUnitPrice,
            mintOwnerResolver = resolver,
            policy = policy,
        )
        return PaymentCredentialHeader(
            headerName = AUTHORIZATION_HEADER,
            headerValue = authorization,
            settlementHeader = PAYMENT_RECEIPT_HEADER,
        )
    }

    companion object {
        const val WWW_AUTHENTICATE_HEADER = "WWW-Authenticate"
        const val AUTHORIZATION_HEADER = "Authorization"
        const val PAYMENT_RECEIPT_HEADER = "Payment-Receipt"
    }
}
