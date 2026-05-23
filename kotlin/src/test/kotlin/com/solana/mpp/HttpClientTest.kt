package com.solana.mpp

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer

class HttpClientTest {
    private lateinit var server: MockWebServer

    @BeforeTest
    fun startServer() {
        server = MockWebServer().apply { start() }
    }

    @AfterTest
    fun stopServer() {
        server.shutdown()
    }

    private val signer = MemorySigner.fromSeed(ByteArray(32) { 0x42 })
    private val blockhashProvider = BlockhashProvider { ByteArray(32) }

    @Test
    fun passesThroughNon402Responses() {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"ok":true}"""))
        val client = MppHttpClient(signer, blockhashProvider)
        val response = client.mppGet(server.url("/free").toString())
        try {
            assertEquals(200, response.code)
            assertEquals("""{"ok":true}""", response.body?.string())
        } finally {
            response.close()
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun retriesWith402ChallengeThenReturnsSuccess() {
        val requestB64 = Base64Url.encode(
            """{"amount":"1000","currency":"SOL","recipient":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY","methodDetails":{"network":"localnet","recentBlockhash":"11111111111111111111111111111111"}}""".encodeToByteArray(),
        )
        val challenge =
            """Payment id="abc", realm="MPP Payment", method="solana", intent="charge", request="$requestB64""""

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("WWW-Authenticate", challenge),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .addHeader("Payment-Receipt", "settled-signature")
                .setBody("""{"fortune":"the harness is wide"}"""),
        )

        val client = MppHttpClient(signer, blockhashProvider)
        val response = client.mppGet(server.url("/paid").toString())
        try {
            assertEquals(200, response.code)
            assertEquals("settled-signature", response.header("Payment-Receipt"))
        } finally {
            response.close()
        }

        assertEquals(2, server.requestCount)
        // Drop the initial request.
        server.takeRequest()
        val retry = server.takeRequest()
        val authorization = retry.getHeader("Authorization")
            ?: throw AssertionError("retry missing Authorization header")
        assertTrue(authorization.startsWith("Payment "))
    }

    @Test
    fun raisesWhenChallengeHeaderMissing() {
        server.enqueue(MockResponse().setResponseCode(402))
        val client = MppHttpClient(signer, blockhashProvider)
        assertFailsWith<MppException.InvalidPaymentScheme> {
            client.mppGet(server.url("/paid").toString()).close()
        }
    }

    @Test
    fun doesNotRetryOn5xx() {
        server.enqueue(MockResponse().setResponseCode(503).setBody("upstream down"))
        val client = MppHttpClient(signer, blockhashProvider)
        val response = client.mppGet(server.url("/down").toString())
        try {
            assertEquals(503, response.code)
        } finally {
            response.close()
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun doesNotRetryOnOther4xx() {
        server.enqueue(MockResponse().setResponseCode(404).setBody("not here"))
        val client = MppHttpClient(signer, blockhashProvider)
        val response = client.mppGet(server.url("/missing").toString())
        try {
            assertEquals(404, response.code)
        } finally {
            response.close()
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun jsonRpcClientParsesGetLatestBlockhashResponse() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """{"jsonrpc":"2.0","id":1,"result":{"context":{"slot":1},"value":{"blockhash":"11111111111111111111111111111111","lastValidBlockHeight":0}}}""",
                ),
        )
        val rpc = JsonRpcClient(server.url("/").toString())
        val blockhash = rpc.fetchRecentBlockhash()
        assertEquals(32, blockhash.size)
        assertTrue(blockhash.all { it == 0.toByte() })
    }

    @Test
    fun jsonRpcClientReportsErrorEnvelope() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}""",
                ),
        )
        val rpc = JsonRpcClient(server.url("/").toString())
        assertFailsWith<MppException.InvalidTransaction> { rpc.fetchRecentBlockhash() }
    }

    @Test
    fun jsonRpcClientSendTransactionReturnsSignature() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """{"jsonrpc":"2.0","id":1,"result":"3LkVA4tQiB...mockSignatureBase58"}""",
                ),
        )
        val rpc = JsonRpcClient(server.url("/").toString())
        val signature = rpc.sendTransaction("AAA=")
        assertEquals("3LkVA4tQiB...mockSignatureBase58", signature)
    }
}
