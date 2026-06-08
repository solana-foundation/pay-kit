package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.client.PayKitClient
import com.solana.paykit.paycore.Base64Url
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.MppException

import kotlinx.coroutines.runBlocking
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer

/**
 * MPP charge client tests, driving the unified [PayKitClient] with a
 * [PayKitClient.Builder.charge] interceptor.
 *
 * Regression fixture for Greptile P1 comment 3293054077:
 * doesNotLeakConnectionOnMissingChallengeHeader exercises the
 * malformed-server branch where a 402 lands without a WWW-Authenticate
 * header. The payment interceptor reads (and so closes) the buffered 402
 * body before building the credential, so the underlying OkHttp connection
 * is released even when the charge build throws InvalidPaymentScheme.
 */
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

    private fun chargeClient(
        provider: BlockhashProvider = blockhashProvider,
        mintOwnerResolver: MintOwnerResolver? = null,
        okHttp: OkHttpClient = OkHttpClient(),
    ): PayKitClient = PayKitClient.Builder()
        .signer(signer)
        .okHttpClient(okHttp)
        .charge(blockhashProvider = provider, mintOwnerResolver = mintOwnerResolver)
        .build()

    @Test
    fun passesThroughNon402Responses() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(200).setBody("""{"ok":true}"""))
        val client = chargeClient()
        val result = client.get(server.url("/free").toString())
        try {
            assertEquals(200, result.status)
            assertNull(result.settlement)
            assertEquals(false, result.paymentSent)
            assertEquals("""{"ok":true}""", result.response.body?.string())
        } finally {
            result.response.close()
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun retriesWith402ChallengeThenReturnsSuccess() = runBlocking {
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

        val client = chargeClient()
        val result = client.get(server.url("/paid").toString())
        try {
            assertEquals(200, result.status)
            assertTrue(result.paymentSent)
            assertEquals("settled-signature", result.settlement)
            assertEquals("settled-signature", result.response.header("Payment-Receipt"))
        } finally {
            result.response.close()
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
    fun selectsSolanaChargeChallengeAmongMultipleHeaders() = runBlocking {
        // Server advertises Basic AND Payment as two distinct
        // WWW-Authenticate headers (RFC 9110 form). The interceptor
        // must walk every header and pick the Solana charge one.
        val requestB64 = Base64Url.encode(
            """{"amount":"1000","currency":"SOL","recipient":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY","methodDetails":{"network":"localnet","recentBlockhash":"11111111111111111111111111111111"}}""".encodeToByteArray(),
        )
        val challenge =
            """Payment id="abc", realm="MPP Payment", method="solana", intent="charge", request="$requestB64""""

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("WWW-Authenticate", """Basic realm="example"""")
                .addHeader("WWW-Authenticate", challenge),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .addHeader("Payment-Receipt", "settled-signature")
                .setBody("""{"fortune":"multi challenge"}"""),
        )

        val client = chargeClient()
        val result = client.get(server.url("/paid-multi-header").toString())
        try {
            assertEquals(200, result.status)
        } finally {
            result.response.close()
        }

        assertEquals(2, server.requestCount)
        server.takeRequest()
        val retry = server.takeRequest()
        val authorization = retry.getHeader("Authorization")
            ?: throw AssertionError("retry missing Authorization header")
        assertTrue(authorization.startsWith("Payment "))
    }

    @Test
    fun selectsSolanaChargeChallengeAmongCommaJoinedSchemes() = runBlocking {
        // Some intermediaries collapse multiple WWW-Authenticate
        // headers into one comma-joined value. The client must split
        // those back out and pick the Solana charge challenge.
        val requestB64 = Base64Url.encode(
            """{"amount":"1000","currency":"SOL","recipient":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY","methodDetails":{"network":"localnet","recentBlockhash":"11111111111111111111111111111111"}}""".encodeToByteArray(),
        )
        val joined =
            """Bearer realm="api", Payment id="abc", realm="MPP Payment", method="solana", intent="charge", request="$requestB64""""

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("WWW-Authenticate", joined),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("ok"),
        )

        val client = chargeClient()
        val result = client.get(server.url("/paid-joined").toString())
        try {
            assertEquals(200, result.status)
        } finally {
            result.response.close()
        }
        assertEquals(2, server.requestCount)
    }

    @Test
    fun forwardsMintOwnerResolverForArbitraryMintChallenge() = runBlocking {
        // Regression for the round-1 token-program fix: Charge now requires a
        // MintOwnerResolver for any mint outside the static stablecoin table.
        // The interceptor forwards a resolver (explicit, or the
        // BlockhashProvider when it implements both), so the retry succeeds.
        val arbitraryMint = "951kD1xQhvXxVxRdJjDgoWi5LnMmLdnDpzd82y3u5ATX"
        val requestB64 = Base64Url.encode(
            (
                """{"amount":"1000","currency":"$arbitraryMint",""" +
                    """"recipient":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",""" +
                    """"methodDetails":{"network":"localnet",""" +
                    """"recentBlockhash":"11111111111111111111111111111111"}}"""
                ).encodeToByteArray(),
        )
        val challenge =
            """Payment id="abc", realm="MPP Payment", method="solana", intent="charge", request="$requestB64""""

        class CombinedProvider : BlockhashProvider, MintOwnerResolver {
            var resolved = false
            override fun fetchRecentBlockhash(): ByteArray = ByteArray(32)
            override fun fetchMintOwner(mintBase58: String): String {
                resolved = true
                return "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            }
        }
        val provider = CombinedProvider()

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("WWW-Authenticate", challenge),
        )
        server.enqueue(MockResponse().setResponseCode(200).setBody("ok"))

        val client = chargeClient(provider = provider, mintOwnerResolver = provider)
        val result = client.get(server.url("/arbitrary-mint").toString())
        try {
            assertEquals(200, result.status)
        } finally {
            result.response.close()
        }
        assertEquals(2, server.requestCount)
        assertTrue(provider.resolved, "MintOwnerResolver must be invoked for the arbitrary mint")
    }

    @Test
    fun arbitraryMintChallengeFailsWithoutResolver() {
        // Companion to forwardsMintOwnerResolverForArbitraryMintChallenge: with
        // no resolver wired (neither explicit nor via the BlockhashProvider),
        // the arbitrary-mint charge must fail closed rather than guessing the
        // token program.
        val arbitraryMint = "951kD1xQhvXxVxRdJjDgoWi5LnMmLdnDpzd82y3u5ATX"
        val requestB64 = Base64Url.encode(
            (
                """{"amount":"1000","currency":"$arbitraryMint",""" +
                    """"recipient":"CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",""" +
                    """"methodDetails":{"network":"localnet",""" +
                    """"recentBlockhash":"11111111111111111111111111111111"}}"""
                ).encodeToByteArray(),
        )
        val challenge =
            """Payment id="abc", realm="MPP Payment", method="solana", intent="charge", request="$requestB64""""

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .addHeader("WWW-Authenticate", challenge),
        )
        // blockhashProvider here is a plain lambda that is NOT a MintOwnerResolver.
        val client = chargeClient()
        assertFailsWith<MppException.InvalidTransaction> {
            runBlocking { client.get(server.url("/arbitrary-mint-no-resolver").toString()).response.close() }
        }
    }

    @Test
    fun raisesWhenChallengeHeaderMissing() {
        server.enqueue(MockResponse().setResponseCode(402))
        val client = chargeClient()
        assertFailsWith<MppException.InvalidPaymentScheme> {
            runBlocking { client.get(server.url("/paid").toString()).response.close() }
        }
    }

    @Test
    fun doesNotLeakConnectionOnMissingChallengeHeader() {
        // Regression for Greptile comment 3293054077. A 402 without a
        // WWW-Authenticate header used to read the body once and throw
        // without closing it, leaking the OkHttp connection.
        //
        // The payment interceptor reads the 402 body via Response.bytes(),
        // which fully reads AND closes the body, releasing the connection
        // back to the pool before it throws InvalidPaymentScheme. OkHttp's
        // EventListener fires connectionReleased exactly once per connection
        // when it is released; the assertion checks that count is 1 even on
        // the throwing path.
        val connectionsReleased = java.util.concurrent.atomic.AtomicInteger(0)
        val listener = object : okhttp3.EventListener() {
            override fun connectionReleased(call: okhttp3.Call, connection: okhttp3.Connection) {
                connectionsReleased.incrementAndGet()
            }
        }
        val okHttp = OkHttpClient.Builder()
            .eventListener(listener)
            .build()
        val client = chargeClient(okHttp = okHttp)

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .setBody("malformed 402 body without WWW-Authenticate"),
        )
        assertFailsWith<MppException.InvalidPaymentScheme> {
            runBlocking { client.get(server.url("/paid").toString()).response.close() }
        }

        assertEquals(
            1,
            connectionsReleased.get(),
            "Connection must be released even when WWW-Authenticate is missing",
        )
    }

    @Test
    fun doesNotRetryOn5xx() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(503).setBody("upstream down"))
        val client = chargeClient()
        val result = client.get(server.url("/down").toString())
        try {
            assertEquals(503, result.status)
            assertEquals(false, result.paymentSent)
        } finally {
            result.response.close()
        }
        assertEquals(1, server.requestCount)
    }

    @Test
    fun doesNotRetryOnOther4xx() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(404).setBody("not here"))
        val client = chargeClient()
        val result = client.get(server.url("/missing").toString())
        try {
            assertEquals(404, result.status)
        } finally {
            result.response.close()
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
    fun jsonRpcClientWrapsNonJsonResponseInMppException() {
        // Regression: a load-balancer 503 HTML page (or any non-JSON
        // body) used to leak a raw kotlinx.serialization
        // SerializationException out of JsonRpcClient.post(). After the
        // fix, the parse step wraps the failure in
        // MppException.InvalidTransaction.
        server.enqueue(
            MockResponse()
                .setResponseCode(503)
                .setBody("<html><body>Service Unavailable</body></html>"),
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
