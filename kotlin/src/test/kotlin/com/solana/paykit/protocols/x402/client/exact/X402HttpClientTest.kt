package com.solana.paykit.protocols.x402.client.exact

import com.solana.paykit.client.PayKitClient
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.Network
import java.util.Base64
import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer

/**
 * x402 ``exact`` client tests, driving the unified [PayKitClient] with a
 * [PayKitClient.Builder.x402] interceptor.
 *
 * Transport: on a 402 response with a ``payment-required`` header or
 * ``accepts[]`` JSON body the client must parse the challenge, build and
 * sign a payment header, and replay the request exactly once with that
 * ``Payment-Signature`` header.
 *
 * Mirrors the Python PaymentTransport tests and the Rust
 * ``harness_client.rs`` end-to-end flow.
 */
class X402HttpClientTest {

    private lateinit var server: MockWebServer

    @BeforeTest
    fun startServer() {
        server = MockWebServer().apply { start() }
    }

    @AfterTest
    fun stopServer() {
        server.shutdown()
    }

    private val signer = MemorySigner.fromSeed(ByteArray(32) { 0x17 })
    private val fixedBlockhash: () -> ByteArray = { ByteArray(32) }

    private fun defaultClient(
        selection: ChallengeSelection = ChallengeSelection(network = "devnet"),
    ): PayKitClient = PayKitClient.Builder()
        .signer(signer)
        .x402(rpcBlockhashProvider = fixedBlockhash, selection = selection)
        .build()

    // ── Challenge envelope helpers ────────────────────────────────────────────

    private fun devnetChallenge(): String {
        val json = """{"accepts":[{
            "scheme":"exact",
            "network":"${Network.SOLANA_DEVNET}",
            "asset":"SOL",
            "amount":"1000",
            "payTo":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        }]}"""
        return Base64.getEncoder().encodeToString(json.toByteArray())
    }

    // ── Non-402 passthrough ───────────────────────────────────────────────────

    @Test
    fun passesThroughNon402Response() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"ok":true}"""))
        val client = defaultClient()
        val result = client.get(server.url("/free").toString())
        try {
            assertEquals(200, result.status)
            assertEquals(false, result.paymentSent, "no payment should be sent for a 200")
        } finally {
            result.response.close()
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun passesThroughOther4xxWithoutRetry() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(404).setBody("not found"))
        val client = defaultClient()
        val result = client.get(server.url("/missing").toString())
        try {
            assertEquals(404, result.status)
            assertEquals(false, result.paymentSent)
        } finally {
            result.response.close()
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun passesThroughServerErrorWithoutRetry() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(503).setBody("down"))
        val client = defaultClient()
        val result = client.get(server.url("/down").toString())
        try {
            assertEquals(503, result.status)
            assertEquals(false, result.paymentSent)
        } finally {
            result.response.close()
        }
        assertEquals(1, server.requestCount)
    }

    // ── 402 retry with Payment-Required header ────────────────────────────────

    @Test
    fun retries402WithPaymentSignatureHeader() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("payment-required", devnetChallenge()),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .addHeader("Payment-Response", "mock-settlement-sig")
                .setBody("""{"data":"unlocked"}"""),
        )

        val client = defaultClient()
        val result = client.get(server.url("/paid").toString())
        try {
            assertEquals(200, result.status)
            assertTrue(result.paymentSent)
            assertEquals("mock-settlement-sig", result.settlement)
        } finally {
            result.response.close()
        }

        assertEquals(2, server.requestCount)
        server.takeRequest() // discard initial request
        val retryRequest = server.takeRequest()
        val sentHeader = retryRequest.getHeader("Payment-Signature")
        assertNotNull(sentHeader, "retry must carry Payment-Signature header")
        assertTrue(sentHeader.isNotEmpty())
    }

    @Test
    fun retries402WithAcceptsJsonBody() = runBlocking {
        val body = """{"accepts":[{
            "scheme":"exact",
            "network":"${Network.SOLANA_DEVNET}",
            "asset":"SOL",
            "amount":"1",
            "payTo":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        }]}"""

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .setBody(body),
        )
        server.enqueue(MockResponse().setResponseCode(200).setBody("ok"))

        val result = defaultClient().get(server.url("/paid-body").toString())
        try {
            assertEquals(200, result.status)
            assertTrue(result.paymentSent)
        } finally {
            result.response.close()
        }
        assertEquals(2, server.requestCount)
    }

    @Test
    fun paymentSignatureHeaderNameIsExact() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("payment-required", devnetChallenge()),
        )
        server.enqueue(MockResponse().setResponseCode(200))

        defaultClient().get(server.url("/paid").toString()).response.close()

        server.takeRequest()
        val retry = server.takeRequest()
        // Header name must be exactly "Payment-Signature" (case-sensitive for OkHttp).
        assertNotNull(retry.getHeader("Payment-Signature"))
        assertNull(retry.getHeader("X-Payment"), "must not use old X-Payment header name")
    }

    // ── 402 without a valid challenge ─────────────────────────────────────────

    @Test
    fun returnsOriginal402WhenChallengeIsMissing() = runBlocking {
        // 402 with no payment-required header and no JSON body: the client
        // cannot satisfy it, so it returns the original 402 (go/python
        // contract) rather than throwing. The body must stay readable.
        server.enqueue(MockResponse().setResponseCode(402).setBody("pay up"))
        val client = defaultClient()
        val result = client.get(server.url("/no-challenge").toString())
        try {
            assertEquals(402, result.status, "original 402 must be handed back")
            assertEquals(false, result.paymentSent, "no payment was sent")
            assertEquals("pay up", result.response.body?.string(), "body must be re-readable")
        } finally {
            result.response.close()
        }
        assertEquals(1, server.requestCount, "must not retry when no challenge matched")
    }

    @Test
    fun returnsOriginal402WhenNoChallengeMatchesSelection() = runBlocking {
        // Server offers mainnet; client selection targets devnet-only USDT.
        val mainnetBody = """{"accepts":[{
            "scheme":"exact",
            "network":"${Network.SOLANA_MAINNET}",
            "asset":"SOL",
            "amount":"1",
            "payTo":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        }]}"""
        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader(
                    "payment-required",
                    Base64.getEncoder().encodeToString(mainnetBody.toByteArray()),
                )
                .setBody("nope"),
        )
        // Client selection: devnet-only currencies list → no match → return 402.
        val client = PayKitClient.Builder()
            .signer(signer)
            .x402(
                rpcBlockhashProvider = fixedBlockhash,
                selection = ChallengeSelection(network = "devnet", currencies = listOf("USDT")),
            )
            .build()
        val result = client.get(server.url("/mismatch").toString())
        try {
            assertEquals(402, result.status)
            assertEquals(false, result.paymentSent)
            assertEquals("nope", result.response.body?.string())
        } finally {
            result.response.close()
        }
        assertEquals(1, server.requestCount)
    }

    // ── settlement field ──────────────────────────────────────────────────────

    @Test
    fun paymentSentMatchesRetryHeader() = runBlocking {
        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("payment-required", devnetChallenge()),
        )
        server.enqueue(MockResponse().setResponseCode(200))

        val result = defaultClient().get(server.url("/paid").toString())
        try {
            assertTrue(result.paymentSent)
            server.takeRequest()
            val retry = server.takeRequest()
            assertNotNull(
                retry.getHeader("Payment-Signature"),
                "a payment was sent, so the retry must carry Payment-Signature",
            )
        } finally {
            result.response.close()
        }
    }

    // ── Extra headers ─────────────────────────────────────────────────────────

    @Test
    fun extraHeadersAreForwardedOnInitialRequest() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200))
        defaultClient().get(
            server.url("/").toString(),
            headers = mapOf("X-Custom-Header" to "hello"),
        ).response.close()

        val recorded = server.takeRequest()
        assertEquals("hello", recorded.getHeader("X-Custom-Header"))
    }
}

/**
 * Unit tests for [X402RpcClient].
 *
 * Verifies blockhash fetching and error handling without a live network.
 */
class X402RpcClientTest {

    private lateinit var server: MockWebServer

    @BeforeTest
    fun startServer() {
        server = MockWebServer().apply { start() }
    }

    @AfterTest
    fun stopServer() {
        server.shutdown()
    }

    private fun client() = X402RpcClient(server.url("/").toString())

    @Test
    fun parsesGetLatestBlockhashSuccessfully() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":0}}}""",
            ),
        )
        val blockhash = client().fetchRecentBlockhash()
        assertEquals(32, blockhash.size)
        assertTrue(blockhash.all { it == 0.toByte() }, "all-zero blockhash expected")
    }

    @Test
    fun throwsOnRpcError() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}""",
            ),
        )
        assertFailsWith<Exception> { client().fetchRecentBlockhash() }
    }

    @Test
    fun throwsOnNonJsonBody() {
        server.enqueue(
            MockResponse()
                .setResponseCode(503)
                .setBody("<html><body>Service Unavailable</body></html>"),
        )
        assertFailsWith<Exception> { client().fetchRecentBlockhash() }
    }

    @Test
    fun throwsOnMissingBlockhashField() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{}}}""",
            ),
        )
        assertFailsWith<Exception> { client().fetchRecentBlockhash() }
    }

    @Test
    fun throwsOnInvalidBase58Blockhash() {
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"0OIl!!!"}}}""",
            ),
        )
        assertFailsWith<Exception> { client().fetchRecentBlockhash() }
    }

    @Test
    fun throwsOnWrongLengthBlockhash() {
        // "111" decodes to fewer than 32 bytes in base58 → size check must fire.
        server.enqueue(
            MockResponse().setResponseCode(200).setBody(
                """{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"111"}}}""",
            ),
        )
        assertFailsWith<Exception> { client().fetchRecentBlockhash() }
    }
}
