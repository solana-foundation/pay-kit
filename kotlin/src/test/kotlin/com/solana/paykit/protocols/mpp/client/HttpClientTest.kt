package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.Base64Url
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.MppException

import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer

/**
 * MppHttpClient unit tests.
 *
 * Regression fixture for Greptile P1 comment 3293054077:
 * doesNotLeakConnectionOnMissingChallengeHeader exercises the
 * malformed-server branch where a 402 lands without a WWW-Authenticate
 * header. Before the use {} fix in HttpClient.kt:52 the OkHttp Response
 * body was read once and dropped on the floor without being closed, which
 * leaked the underlying connection. The regression test asserts a
 * follow-up request on the same client succeeds, which would surface a
 * "stream already closed" or socket reset if the bug recurred.
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
    fun selectsSolanaChargeChallengeAmongMultipleHeaders() {
        // Server advertises Basic AND Payment as two distinct
        // WWW-Authenticate headers (RFC 9110 form). The Kotlin
        // client used to read only the first header and abort on
        // the non-Payment one; this regression locks in the
        // multi-header selection fix.
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

        val client = MppHttpClient(signer, blockhashProvider)
        val response = client.mppGet(server.url("/paid-multi-header").toString())
        try {
            assertEquals(200, response.code)
        } finally {
            response.close()
        }

        assertEquals(2, server.requestCount)
        server.takeRequest()
        val retry = server.takeRequest()
        val authorization = retry.getHeader("Authorization")
            ?: throw AssertionError("retry missing Authorization header")
        assertTrue(authorization.startsWith("Payment "))
    }

    @Test
    fun selectsSolanaChargeChallengeAmongCommaJoinedSchemes() {
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

        val client = MppHttpClient(signer, blockhashProvider)
        val response = client.mppGet(server.url("/paid-joined").toString())
        try {
            assertEquals(200, response.code)
        } finally {
            response.close()
        }
        assertEquals(2, server.requestCount)
    }

    @Test
    fun forwardsMintOwnerResolverForArbitraryMintChallenge() {
        // Regression for the round-1 token-program fix: Charge now requires a
        // MintOwnerResolver for any mint outside the static stablecoin table.
        // MppHttpClient used to forward only the BlockhashProvider, so an
        // arbitrary-mint charge challenge threw InvalidTransaction
        // ("no MintOwnerResolver was provided") on the retry step. After the
        // fix the client forwards a resolver and the retry succeeds.
        //
        // Arbitrary mint: a valid base58 pubkey that is NOT a known stablecoin
        // and carries no pinned methodDetails.tokenProgram, so the charge
        // builder must resolve the token program from the mint account owner.
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

        // A provider that resolves both the blockhash and the mint owner,
        // mirroring JsonRpcClient (which implements both interfaces). The owner
        // is the legacy SPL Token program so the charge builder accepts it.
        class CombinedProvider :
            com.solana.paykit.protocols.mpp.client.BlockhashProvider,
            com.solana.paykit.protocols.mpp.client.MintOwnerResolver {
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

        val client = MppHttpClient(signer, provider, mintOwnerResolver = provider)
        val response = client.mppGet(server.url("/arbitrary-mint").toString())
        try {
            assertEquals(200, response.code)
        } finally {
            response.close()
        }
        assertEquals(2, server.requestCount)
        assertTrue(provider.resolved, "MintOwnerResolver must be invoked for the arbitrary mint")
    }

    @Test
    fun arbitraryMintChallengeFailsWithoutResolver() {
        // Companion to forwardsMintOwnerResolverForArbitraryMintChallenge: with
        // no resolver wired (neither explicit nor via the BlockhashProvider),
        // the arbitrary-mint charge must fail closed rather than guessing the
        // token program. Locks in that the resolver is genuinely required.
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
        val client = MppHttpClient(signer, blockhashProvider)
        assertFailsWith<MppException.InvalidTransaction> {
            client.mppGet(server.url("/arbitrary-mint-no-resolver").toString()).close()
        }
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
    fun doesNotLeakConnectionOnMissingChallengeHeader() {
        // Regression for Greptile comment 3293054077. A 402 without a
        // WWW-Authenticate header used to read the body once and throw
        // without closing it, leaking the OkHttp connection.
        //
        // OkHttp's EventListener fires connectionReleased exactly once
        // per connection when the call releases it back to the pool
        // (or closes it). If mppGet throws on the missing-header branch
        // without closing the response, the connection is never
        // released; the listener count stays at zero, which the
        // assertion catches directly. The 402 body is non-empty so
        // OkHttp must close it explicitly rather than treating it as a
        // zero-byte natural completion.
        val connectionsReleased = java.util.concurrent.atomic.AtomicInteger(0)
        val listener = object : okhttp3.EventListener() {
            override fun connectionReleased(call: okhttp3.Call, connection: okhttp3.Connection) {
                connectionsReleased.incrementAndGet()
            }
        }
        val okHttp = OkHttpClient.Builder()
            .eventListener(listener)
            .build()
        val client = MppHttpClient(signer, blockhashProvider, okHttp)

        server.enqueue(
            MockResponse()
                .setResponseCode(402)
                .setBody("malformed 402 body without WWW-Authenticate"),
        )
        assertFailsWith<MppException.InvalidPaymentScheme> {
            client.mppGet(server.url("/paid").toString()).close()
        }

        assertEquals(
            1,
            connectionsReleased.get(),
            "Connection must be released even when WWW-Authenticate is missing",
        )
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
    fun jsonRpcClientWrapsNonJsonResponseInMppException() {
        // Regression: a load-balancer 503 HTML page (or any non-JSON
        // body) used to leak a raw kotlinx.serialization
        // SerializationException out of JsonRpcClient.post(). Callers
        // catching MppException to handle network failures would
        // silently miss it. After the fix, the parse step wraps the
        // failure in MppException.InvalidTransaction.
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
