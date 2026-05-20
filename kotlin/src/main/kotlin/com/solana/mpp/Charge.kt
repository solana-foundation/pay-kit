package com.solana.mpp

fun interface ChargeTransactionProvider {
    fun buildTransaction(request: ChargeRequest): String
}

class ChargeCredentialBuilder(private val transactionProvider: ChargeTransactionProvider) {
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
