package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.Base64Url
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.MppException
import com.solana.paykit.protocols.mpp.core.ChargeRequest
import com.solana.paykit.protocols.mpp.core.ChallengeEcho
import com.solana.paykit.protocols.mpp.core.CredentialPayload
import com.solana.paykit.protocols.mpp.core.MppHeaders
import com.solana.paykit.protocols.mpp.core.PaymentChallenge
import com.solana.paykit.protocols.mpp.core.PaymentCredential
import com.solana.paykit.protocols.mpp.core.SolanaChargeMethodDetails

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import java.security.KeyPairGenerator
import java.security.PublicKey

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
        val methodDetails = request.methodDetails!!
        assertEquals("localnet", methodDetails.network)
        assertEquals("250", methodDetails.splits?.first()?.amount)
        assertEquals(true, methodDetails.splits?.first()?.ataCreationRequired)
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
    fun memorySignerExposesPublicKeyAsBase64UrlAndBase58() {
        val signer = MemorySigner.generate()
        val publicKey = Base64Url.decode(signer.publicKey)
        val address = Base58.decode(signer.address)

        assertEquals(32, publicKey.size)
        assertContentEquals(publicKey, address)
        assertContentEquals(publicKey, signer.publicKeyBytes)
    }

    @Test
    fun memorySignerFromKeyPairRejectsJdkEd25519() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        // The JDK does not expose the raw 32 byte seed, so the helper
        // must refuse rather than silently fabricate a different signer.
        val error = assertFailsWith<IllegalArgumentException> {
            MemorySigner.fromKeyPair(keyPair)
        }
        assertTrue((error.message ?: "").contains("fromSeed") || (error.message ?: "").contains("fromSecretKey"))
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

    @Test
    fun rejectsInvalidPaymentScheme() {
        assertFailsWith<MppException.InvalidPaymentScheme> {
            MppHeaders.parseWWWAuthenticate("""Bearer id="challenge-5"""")
        }
    }

    @Test
    fun rejectsMissingRequiredChallengeFields() {
        assertFailsWith<MppException.MissingField> {
            MppHeaders.parseWWWAuthenticate(
                """Payment id="challenge-6", realm="MPP Payment", method="solana", request="${encodedRequest()}"""",
            )
        }
    }

    @Test
    fun rejectsInvalidChargeRequestJson() {
        val encoded = Base64Url.encode("not json".encodeToByteArray())

        assertFailsWith<MppException.InvalidJson> {
            MppHeaders.parseWWWAuthenticate(
                """Payment id="challenge-7", realm="MPP Payment", method="solana", intent="charge", request="$encoded"""",
            ).chargeRequest()
        }
    }

    @Test
    fun parsesOptionalChallengeFieldsAndSignaturePayload() {
        val header = """Payment id="challenge-8", realm="MPP \"Payment\"", method="solana", intent="charge", request="${encodedRequest()}", digest="sha-256=:abc:", opaque="route-1""""
        val challenge = MppHeaders.parseWWWAuthenticate(header)
        val credential = PaymentCredential(
            challenge = challenge.echo(),
            payload = CredentialPayload.signature("sig"),
            source = "did:pkh:solana:test",
        )
        val decoded = Json.decodeFromString<PaymentCredential>(
            Base64Url.decode(MppHeaders.formatAuthorization(credential).removePrefix("Payment ")).decodeToString(),
        )

        assertEquals("""MPP "Payment"""", challenge.realm)
        assertEquals("sha-256=:abc:", challenge.digest)
        assertEquals("route-1", challenge.opaque)
        assertEquals("sig", decoded.payload.signature)
        assertEquals("did:pkh:solana:test", decoded.source)
    }

    @Test
    fun rejectsUnterminatedQuotedAuthParam() {
        assertFailsWith<MppException.InvalidHeader> {
            MppHeaders.parseWWWAuthenticate(
                """Payment id="challenge-4", realm="MPP Payment", method="solana", intent="charge", request="${encodedRequest()}""",
            )
        }
    }

    @Test
    fun acceptsUnquotedTokenAuthParam() {
        // RFC 7235 allows auth-param values to be `token` OR
        // `quoted-string`. The Rust reference parser accepts both, so
        // an unquoted `request=<token>` (here a base64url payload
        // which is a valid token) must parse cleanly. Previously this
        // test asserted rejection, which broke interop with compliant
        // peers (see PR #105 codex review, Headers P2).
        val challenge = MppHeaders.parseWWWAuthenticate(
            """Payment id="challenge-9", realm="MPP Payment", method="solana", intent="charge", request=${encodedRequest()}""",
        )
        assertEquals("challenge-9", challenge.id)
        assertEquals("solana", challenge.method)
    }

    @Test
    fun rejectsTrailingEscapeInQuotedAuthParam() {
        assertFailsWith<MppException.InvalidHeader> {
            MppHeaders.parseWWWAuthenticate(
                """Payment id="challenge-10", realm="MPP Payment", method="solana", intent="charge", request="${encodedRequest()}\""",
            )
        }
    }

    @Test
    fun rejectsNonEd25519MemorySignerPublicKey() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()

        assertFailsWith<IllegalArgumentException> {
            MemorySigner.rawEd25519PublicKey(keyPair.public)
        }
    }

    @Test
    fun rejectsMalformedEd25519PublicKeyPrefix() {
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val encoded = keyPair.public.encoded.clone()
        encoded[0] = 0x31
        val publicKey = object : PublicKey {
            override fun getAlgorithm(): String = "Ed25519"
            override fun getFormat(): String = "X.509"
            override fun getEncoded(): ByteArray = encoded
        }

        assertFailsWith<IllegalArgumentException> {
            MemorySigner.rawEd25519PublicKey(publicKey)
        }
    }

    private class StaticChargeTransactionProvider(
        private val transaction: String,
    ) : ChargeTransactionProvider {
        override fun buildTransaction(request: ChargeRequest): String = transaction
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
