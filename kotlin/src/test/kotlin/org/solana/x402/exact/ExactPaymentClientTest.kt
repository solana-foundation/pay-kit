package org.solana.x402.exact

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ExactPaymentClientTest {
    @Test
    fun `creates v2 payment signature header with injected transaction signer`() {
        val builder = RecordingTransactionBuilder(byteArrayOf(1, 2, 3))
        val signer = RecordingTransactionSigner(ByteArray(64) { 9 })
        val client = ExactPaymentClient(builder, signer)

        val headers = client.createPaymentHeaders(
            selected = selectedRequirement(
                extra = mapOf(
                    "feePayer" to "FeePayer1111111111111111111111111111",
                    "memo" to "order-123",
                ),
            ),
            payer = "Payer11111111111111111111111111111111",
        )

        val encoded = assertNotNull(headers["PAYMENT-SIGNATURE"])
        val envelope = JsonParser.parseString(
            String(Base64.getDecoder().decode(encoded), Charsets.UTF_8),
        ).asJsonObject

        assertEquals(2, envelope["x402Version"].asInt)
        assertEquals("exact", envelope["accepted"].asJsonObject["scheme"].asString)
        assertEquals(ExactChallenge.DEFAULT_NETWORK, envelope["accepted"].asJsonObject["network"].asString)
        assertEquals("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", envelope["accepted"].asJsonObject["asset"].asString)
        assertEquals("PayTo111111111111111111111111111111111", envelope["accepted"].asJsonObject["payTo"].asString)
        val transaction = Base64.getDecoder().decode(envelope["payload"].asJsonObject["transaction"].asString)
        assertEquals(68, transaction.size)
        assertEquals(1, transaction[0].toInt())
        assertContentEquals(ByteArray(64) { 9 }, transaction.copyOfRange(1, 65))
        assertContentEquals(byteArrayOf(1, 2, 3), transaction.copyOfRange(65, 68))
        assertEquals("http://127.0.0.1:3000/protected", envelope["resource"].asJsonObject["url"].asString)

        assertEquals(1, builder.requests.size)
        assertEquals("Payer11111111111111111111111111111111", builder.requests.single().payer)
        assertEquals("FeePayer1111111111111111111111111111", builder.requests.single().feePayer)
        assertEquals("order-123", builder.requests.single().memo)
        assertContentEquals(byteArrayOf(1, 2, 3), signer.inputs.single())
    }

    @Test
    fun `rejects missing feePayer before constructing transaction`() {
        val builder = RecordingTransactionBuilder(byteArrayOf(1))
        val signer = RecordingTransactionSigner(byteArrayOf(2))
        val client = ExactPaymentClient(builder, signer)

        val error = assertFailsWith<IllegalArgumentException> {
            client.createPaymentHeaders(
                selected = selectedRequirement(extra = emptyMap()),
                payer = "Payer11111111111111111111111111111111",
            )
        }

        assertEquals("feePayer is required in paymentRequirements.extra for SVM transactions", error.message)
        assertEquals(0, builder.requests.size)
        assertEquals(0, signer.inputs.size)
    }

    @Test
    fun `rejects missing payTo before constructing transaction`() {
        val builder = RecordingTransactionBuilder(byteArrayOf(1))
        val signer = RecordingTransactionSigner(byteArrayOf(2))
        val client = ExactPaymentClient(builder, signer)

        val error = assertFailsWith<IllegalArgumentException> {
            client.createPaymentHeaders(
                selected = selectedRequirement(payTo = null),
                payer = "Payer11111111111111111111111111111111",
            )
        }

        assertEquals("payTo is required for SVM exact payment requirements", error.message)
        assertEquals(0, builder.requests.size)
        assertEquals(0, signer.inputs.size)
    }

    @Test
    fun `rejects oversized memo before constructing transaction`() {
        val builder = RecordingTransactionBuilder(byteArrayOf(1))
        val signer = RecordingTransactionSigner(byteArrayOf(2))
        val client = ExactPaymentClient(builder, signer)

        val error = assertFailsWith<IllegalArgumentException> {
            client.createPaymentHeaders(
                selected = selectedRequirement(
                    extra = mapOf(
                        "feePayer" to "FeePayer1111111111111111111111111111",
                        "memo" to "x".repeat(257),
                    ),
                ),
                payer = "Payer11111111111111111111111111111111",
            )
        }

        assertEquals("extra.memo exceeds maximum 256 bytes", error.message)
        assertEquals(0, builder.requests.size)
        assertEquals(0, signer.inputs.size)
    }

    @Test
    fun `rejects challenge whose feePayer equals payer wallet (managed fee-payer drain attack)`() {
        // Defensive client-side validation: a malicious server may set the managed
        // fee payer to the user's own wallet to make the wallet pay SVM fees on
        // top of the transfer. The exact-svm scheme requires operational
        // separation; reject before any RPC or signing work happens.
        val builder = RecordingTransactionBuilder(byteArrayOf(1))
        val signer = RecordingTransactionSigner(byteArrayOf(2))
        val client = ExactPaymentClient(builder, signer)

        val payer = "Payer11111111111111111111111111111111"
        val error = assertFailsWith<IllegalArgumentException> {
            client.createPaymentHeaders(
                selected = selectedRequirement(extra = mapOf("feePayer" to payer)),
                payer = payer,
            )
        }
        assertEquals(
            "managed fee payer must differ from the transfer authority (payer)",
            error.message,
        )
        assertEquals(0, builder.requests.size)
        assertEquals(0, signer.inputs.size)
    }

    @Test
    fun `client_rejects_self_transfer_when_payTo_equals_payer`() {
        // Money-loss bug regression: when payTo collides with the payer wallet
        // the SPL Token program rejects the transfer on-chain. Fail fast on the
        // client before any Base58 decoding, ATA derivation, or RPC work runs.
        val builder = RecordingTransactionBuilder(byteArrayOf(1))
        val signer = RecordingTransactionSigner(byteArrayOf(2))
        val client = ExactPaymentClient(builder, signer)

        val payer = "Payer11111111111111111111111111111111"
        val error = assertFailsWith<IllegalArgumentException> {
            client.createPaymentHeaders(
                selected = selectedRequirement(payTo = payer),
                payer = payer,
            )
        }
        assertEquals("payTo must differ from payer (self-transfer)", error.message)
        assertEquals(0, builder.requests.size)
        assertEquals(0, signer.inputs.size)
    }

    @Test
    fun `client_rejects_challenge_with_unsupported_tokenProgram`() {
        // P1 security: a malicious server can set extra.tokenProgram to an
        // arbitrary executable program ID. The client must reject anything
        // outside the canonical SPL allowlist (TokenkegQ... / TokenzQd...)
        // before any builder, RPC, or signing work runs.
        val builder = RecordingTransactionBuilder(byteArrayOf(1))
        val signer = RecordingTransactionSigner(byteArrayOf(2))
        val client = ExactPaymentClient(builder, signer)

        val error = assertFailsWith<IllegalArgumentException> {
            client.createPaymentHeaders(
                selected = selectedRequirement(
                    extra = mapOf(
                        "feePayer" to "FeePayer1111111111111111111111111111",
                        "tokenProgram" to "EvilProgram1111111111111111111111111111",
                    ),
                ),
                payer = "Payer11111111111111111111111111111111",
            )
        }
        assertTrue(
            error.message?.contains("unsupported tokenProgram") == true,
            "expected unsupported-tokenProgram rejection, got: ${error.message}",
        )
        assertEquals(0, builder.requests.size)
        assertEquals(0, signer.inputs.size)
    }

    @Test
    fun `client_accepts_challenge_with_canonical_spl_token_program`() {
        val builder = RecordingTransactionBuilder(byteArrayOf(1, 2, 3))
        val signer = RecordingTransactionSigner(ByteArray(64) { 9 })
        val client = ExactPaymentClient(builder, signer)

        client.createPaymentHeaders(
            selected = selectedRequirement(
                extra = mapOf(
                    "feePayer" to "FeePayer1111111111111111111111111111",
                    "tokenProgram" to "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                ),
            ),
            payer = "Payer11111111111111111111111111111111",
        )
        assertEquals(1, builder.requests.size)
    }

    @Test
    fun `client_accepts_challenge_with_canonical_token_2022_program`() {
        val builder = RecordingTransactionBuilder(byteArrayOf(1, 2, 3))
        val signer = RecordingTransactionSigner(ByteArray(64) { 9 })
        val client = ExactPaymentClient(builder, signer)

        client.createPaymentHeaders(
            selected = selectedRequirement(
                extra = mapOf(
                    "feePayer" to "FeePayer1111111111111111111111111111",
                    "tokenProgram" to "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
                ),
            ),
            payer = "Payer11111111111111111111111111111111",
        )
        assertEquals(1, builder.requests.size)
    }

    @Test
    fun `rejects challenge whose payTo equals feePayer (self-pay loop attack)`() {
        val builder = RecordingTransactionBuilder(byteArrayOf(1))
        val signer = RecordingTransactionSigner(byteArrayOf(2))
        val client = ExactPaymentClient(builder, signer)

        val collidingAddress = "PayTo111111111111111111111111111111111"
        val error = assertFailsWith<IllegalArgumentException> {
            client.createPaymentHeaders(
                selected = selectedRequirement(
                    payTo = collidingAddress,
                    extra = mapOf("feePayer" to collidingAddress),
                ),
                payer = "Payer11111111111111111111111111111111",
            )
        }
        assertEquals("payTo must differ from the managed fee payer", error.message)
        assertEquals(0, builder.requests.size)
        assertEquals(0, signer.inputs.size)
    }
}

private class RecordingTransactionBuilder(
    private val message: ByteArray,
) : SolanaExactTransactionBuilder {
    val requests = mutableListOf<SolanaExactPaymentRequest>()

    override fun buildUnsignedTransaction(request: SolanaExactPaymentRequest): UnsignedSolanaTransaction {
        requests.add(request)
        return UnsignedSolanaTransaction(
            message = message,
            signatures = listOf(ByteArray(64)),
            signerIndex = 0,
        )
    }
}

private class RecordingTransactionSigner(
    private val signedTransaction: ByteArray,
) : SolanaTransactionSigner {
    val inputs = mutableListOf<ByteArray>()

    override fun signMessage(message: ByteArray): ByteArray {
        inputs.add(message)
        return signedTransaction
    }
}

private fun selectedRequirement(
    payTo: String? = "PayTo111111111111111111111111111111111",
    extra: Map<String, String> = mapOf("feePayer" to "FeePayer1111111111111111111111111111"),
): SelectedChallenge {
    val raw = JsonObject().apply {
        addProperty("scheme", "exact")
        addProperty("network", ExactChallenge.DEFAULT_NETWORK)
        addProperty("asset", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
        addProperty("amount", "1000")
        if (payTo != null) {
            addProperty("payTo", payTo)
        }
        addProperty("maxTimeoutSeconds", 60)
        add(
            "extra",
            JsonObject().apply {
                extra.forEach { (key, value) -> addProperty(key, value) }
            },
        )
    }

    return SelectedChallenge(
        requirement = PaymentRequirement(
            scheme = "exact",
            network = ExactChallenge.DEFAULT_NETWORK,
            asset = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            amount = "1000",
            payTo = payTo,
            maxTimeoutSeconds = 60,
            extra = raw["extra"].asJsonObject.entrySet().associate { it.key to it.value },
            raw = raw,
        ),
        resource = ResourceInfo(
            url = "http://127.0.0.1:3000/protected",
            description = "fixture",
            mimeType = "application/json",
            raw = JsonObject().apply {
                addProperty("url", "http://127.0.0.1:3000/protected")
                addProperty("description", "fixture")
                addProperty("mimeType", "application/json")
            },
        ),
    )
}
