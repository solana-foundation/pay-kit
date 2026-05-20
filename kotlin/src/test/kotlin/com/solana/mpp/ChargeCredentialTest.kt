package com.solana.mpp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json

class ChargeCredentialTest {
    @Test
    fun parsesChargeChallengeWithSplits() {
        val challenge = MppHeaders.parseWWWAuthenticate(challengeHeader())
        val request = challenge.chargeRequest()

        assertEquals("challenge-1", challenge.id)
        assertEquals("solana", challenge.method)
        assertEquals("charge", challenge.intent)
        assertEquals("1000", request.amount)
        assertEquals("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", request.currency)
        assertEquals("localnet", request.methodDetails.network)
        assertEquals("250", request.methodDetails.splits?.first()?.amount)
        assertEquals(true, request.methodDetails.splits?.first()?.ataCreationRequired)
    }

    @Test
    fun serializesPullModeAuthorizationCredential() {
        val challenge = MppHeaders.parseWWWAuthenticate(challengeHeader())
        val builder = ChargeCredentialBuilder(StaticChargeTransactionProvider("base64-transaction"))

        val header = builder.authorizationHeader(challenge)
        assertTrue(header.startsWith("Payment "))

        val encoded = header.removePrefix("Payment ")
        val credential = Json.decodeFromString<PaymentCredential>(
            Base64Url.decode(encoded).decodeToString(),
        )

        assertEquals(challenge.id, credential.challenge.id)
        assertEquals(challenge.request, credential.challenge.request)
        assertEquals(CredentialPayload.transaction("base64-transaction"), credential.payload)
    }

    @Test
    fun transactionProviderCanUseSolanaSigner() {
        val challenge = MppHeaders.parseWWWAuthenticate(challengeHeader())
        val signer = MemorySigner.generate()
        val builder = ChargeCredentialBuilder(
            ChargeTransactionProvider { request ->
                val message = "${request.externalId}:${request.recipient}:${signer.address}".encodeToByteArray()
                Base64Url.encode(signer.sign(message))
            }
        )

        val encoded = builder.authorizationHeader(challenge).removePrefix("Payment ")
        val credential = Json.decodeFromString<PaymentCredential>(
            Base64Url.decode(encoded).decodeToString(),
        )

        assertEquals("transaction", credential.payload.type)
        assertTrue(credential.payload.transaction?.isNotBlank() == true)
    }

    @Test
    fun rejectsUnsupportedIntent() {
        val challenge = PaymentChallenge(
            id = "challenge-2",
            realm = "MPP Payment",
            method = "solana",
            intent = "session",
            request = encodedRequest(),
        )
        val builder = ChargeCredentialBuilder(StaticChargeTransactionProvider("tx"))

        assertFailsWith<MppException.UnsupportedChallenge> {
            builder.authorizationHeader(challenge)
        }
    }

    @Test
    fun rejectsMalformedRequestBase64() {
        assertFailsWith<MppException.InvalidBase64Url> {
            MppHeaders.parseWWWAuthenticate(
                """Payment id="challenge-3", realm="MPP Payment", method="solana", intent="charge", request="@@@"""",
            )
        }
    }

    private fun challengeHeader(): String =
        """Payment id="challenge-1", realm="MPP Payment", method="solana", intent="charge", request="${encodedRequest()}", expires="2026-05-20T00:00:00Z""""

    private fun encodedRequest(): String =
        Base64Url.encode(
            """
            {
              "amount": "1000",
              "currency": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
              "recipient": "recipient11111111111111111111111111111111",
              "externalId": "order-123",
              "methodDetails": {
                "network": "localnet",
                "decimals": 6,
                "feePayer": true,
                "feePayerKey": "feePayer1111111111111111111111111111111",
                "recentBlockhash": "blockhash11111111111111111111111111111111",
                "splits": [
                  {
                    "recipient": "platform111111111111111111111111111111",
                    "amount": "250",
                    "ataCreationRequired": true,
                    "memo": "interop split"
                  }
                ],
                "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
              }
            }
            """.trimIndent().encodeToByteArray(),
        )
}
