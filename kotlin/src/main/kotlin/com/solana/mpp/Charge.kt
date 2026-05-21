package com.solana.mpp

/** Builds a signed Solana transaction for a decoded MPP charge request. */
fun interface ChargeTransactionProvider {
    /** Returns the signed base64 transaction for the provided charge request. */
    fun buildTransaction(request: ChargeRequest): String
}

/** Creates MPP Authorization credentials from Solana charge challenges. */
class ChargeCredentialBuilder(private val transactionProvider: ChargeTransactionProvider) {
    /** Builds an `Authorization: Payment ...` header for a Solana charge challenge. */
    fun authorizationHeader(challenge: PaymentChallenge): String {
        challenge.requireSolanaCharge()

        val transaction = transactionProvider.buildTransaction(challenge.chargeRequest())
        return MppHeaders.formatAuthorization(
            PaymentCredential(
                challenge = challenge.echo(),
                payload = CredentialPayload.transaction(transaction),
            )
        )
    }
}
