package com.solana.paykit.client

import com.solana.paykit.paycore.SolanaSigner
import com.solana.paykit.protocols.mpp.client.BlockhashProvider
import com.solana.paykit.protocols.mpp.client.MintOwnerResolver
import com.solana.paykit.protocols.x402.client.exact.ChallengeSelection
import com.solana.paykit.protocols.x402.client.exact.X402RpcClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

/**
 * A payment-aware HTTP client for pay-kit, built on OkHttp.
 *
 * Design follows [Retrofit](https://square.github.io/retrofit/): a builder
 * configures the client, payment handling lives in an OkHttp [PaymentInterceptor],
 * and the call surface is a small set of suspend functions returning a typed
 * [PayResponse]. The 402 -> pay -> retry loop is NOT in the call methods; it is
 * an interceptor in the OkHttp chain, exactly how Retrofit/OkHttp model auth
 * and retry.
 *
 * Configure a client for either protocol with [Builder]:
 *
 * ```kotlin
 * // MPP charge:
 * val client = PayKitClient.Builder()
 *     .signer(signer)
 *     .charge(blockhashProvider = JsonRpcClient("https://402.surfnet.dev"))
 *     .build()
 *
 * // x402 exact:
 * val client = PayKitClient.Builder()
 *     .signer(signer)
 *     .x402(rpc = "https://402.surfnet.dev", network = "devnet")
 *     .build()
 *
 * val result = client.get("https://402.surfnet.dev/paid")
 * result.use { body -> println("status ${result.status}: $body") }
 * ```
 *
 * Both protocols ride the same client and call surface; only the configured
 * interceptor differs. A client may carry both interceptors (call both
 * [Builder.charge] and [Builder.x402]); on a 402 they run in registration
 * order and the first to recognise the challenge pays.
 */
class PayKitClient internal constructor(
    private val okHttp: OkHttpClient,
) {
    /**
     * Performs a payment-aware GET. On a 402 the configured interceptor parses
     * the challenge, signs a payment, and replays once. Returns a [PayResponse]
     * whose [PayResponse.response] body the caller must close.
     */
    suspend fun get(url: String, headers: Map<String, String> = emptyMap()): PayResponse =
        call("GET", url, headers, body = null)

    /** Performs a payment-aware POST. See [get]. */
    suspend fun post(
        url: String,
        body: ByteArray? = null,
        contentType: String = "application/octet-stream",
        headers: Map<String, String> = emptyMap(),
    ): PayResponse = call("POST", url, headers, body, contentType)

    private suspend fun call(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray?,
        contentType: String = "application/octet-stream",
    ): PayResponse = withContext(Dispatchers.IO) {
        val requestBody = body?.toRequestBody(contentType.toMediaType())
        val builder = Request.Builder().url(url).method(method, requestBody)
        for ((name, value) in headers) {
            builder.header(name, value)
        }
        val response = okHttp.newCall(builder.build()).execute()
        toPayResponse(response)
    }

    private fun toPayResponse(response: Response): PayResponse {
        // The interceptor stamps synthetic headers when it attached a payment.
        // Strip them from the returned response so callers never see pay-kit
        // internals, and surface them as typed fields instead.
        val paymentSent = response.header(PaymentInterceptor.PAYMENT_SENT_HEADER) == "true"
        val paymentHeader: String?
        val settlement: String?
        if (paymentSent) {
            paymentHeader = response.header(PaymentInterceptor.PAYMENT_HEADER_VALUE)
            settlement = response.header(PaymentInterceptor.SETTLEMENT_HEADER_NAME)
                ?.let { response.header(it) }
        } else {
            paymentHeader = null
            settlement = null
        }
        val cleaned = response.newBuilder()
            .removeHeader(PaymentInterceptor.PAYMENT_SENT_HEADER)
            .removeHeader(PaymentInterceptor.SETTLEMENT_HEADER_NAME)
            .removeHeader(PaymentInterceptor.PAYMENT_HEADER_VALUE)
            .build()
        return PayResponse(
            response = cleaned,
            paymentSent = paymentSent,
            paymentHeader = paymentHeader,
            settlement = settlement,
        )
    }

    /**
     * Builds a [PayKitClient]. Mirrors ``Retrofit.Builder`` /
     * ``OkHttpClient.Builder``: chain configuration calls, then [build].
     *
     * [signer] is required. At least one protocol ([charge] or [x402]) must be
     * configured. Custom OkHttp configuration (timeouts, logging, proxies) goes
     * through [okHttpClient], onto which the payment interceptor is layered.
     */
    class Builder {
        private var signer: SolanaSigner? = null
        private var baseOkHttp: OkHttpClient = OkHttpClient()
        private val interceptors = mutableListOf<PaymentInterceptor>()

        /** Sets the Solana signer used to sign payment transactions. Required. */
        fun signer(signer: SolanaSigner): Builder = apply { this.signer = signer }

        /**
         * Supplies the base OkHttp client to layer the payment interceptor onto.
         * Use this to configure timeouts, logging, proxies, or connection pools;
         * pay-kit adds only its payment interceptor on top.
         */
        fun okHttpClient(client: OkHttpClient): Builder = apply { this.baseOkHttp = client }

        /**
         * Enables the MPP charge protocol.
         *
         * @param blockhashProvider supplies a recent blockhash when the
         *   challenge omits one (``JsonRpcClient`` implements it).
         * @param computeUnitLimit ComputeBudget unit limit (default 200_000).
         * @param computeUnitPrice ComputeBudget unit price (default 1).
         * @param mintOwnerResolver resolves the token program for arbitrary
         *   mints; defaults to [blockhashProvider] when it also implements
         *   [MintOwnerResolver].
         */
        fun charge(
            blockhashProvider: BlockhashProvider,
            computeUnitLimit: Int = DEFAULT_COMPUTE_UNIT_LIMIT,
            computeUnitPrice: Long = DEFAULT_COMPUTE_UNIT_PRICE,
            mintOwnerResolver: MintOwnerResolver? = null,
        ): Builder = apply {
            interceptors.add(
                ChargeInterceptor(
                    signer = requireSigner(),
                    blockhashProvider = blockhashProvider,
                    computeUnitLimit = computeUnitLimit,
                    computeUnitPrice = computeUnitPrice,
                    mintOwnerResolver = mintOwnerResolver,
                ),
            )
        }

        /**
         * Enables the x402 ``exact`` protocol.
         *
         * @param rpcBlockhashProvider supplies a recent blockhash when the
         *   offer omits ``extra.recentBlockhash``.
         * @param selection currency / network preferences for picking an offer.
         */
        fun x402(
            rpcBlockhashProvider: () -> ByteArray,
            selection: ChallengeSelection = ChallengeSelection(),
        ): Builder = apply {
            interceptors.add(
                X402Interceptor(
                    signer = requireSigner(),
                    rpcBlockhashProvider = rpcBlockhashProvider,
                    selection = selection,
                ),
            )
        }

        /**
         * Enables the x402 ``exact`` protocol against a JSON-RPC [rpc]
         * endpoint, fetching a recent blockhash only when an offer omits one.
         *
         * @param rpc Solana JSON-RPC URL (e.g. ``https://402.surfnet.dev``).
         * @param network Solana network slug for offer selection (``null``
         *   defaults to mainnet; pass ``"devnet"`` for Surfpool/devnet).
         * @param currencies priority-ordered currencies to pay in, or ``null``
         *   for cheapest-offer selection.
         */
        fun x402(
            rpc: String,
            network: String? = null,
            currencies: List<String>? = null,
        ): Builder {
            val rpcClient = X402RpcClient(rpc)
            return x402(
                rpcBlockhashProvider = { rpcClient.fetchRecentBlockhash() },
                selection = ChallengeSelection(network = network, currencies = currencies),
            )
        }

        /** Builds the configured [PayKitClient]. */
        fun build(): PayKitClient {
            requireSigner()
            require(interceptors.isNotEmpty()) {
                "configure at least one protocol via charge(...) or x402(...)"
            }
            val builder = baseOkHttp.newBuilder()
            for (interceptor in interceptors) {
                builder.addInterceptor(interceptor)
            }
            return PayKitClient(builder.build())
        }

        private fun requireSigner(): SolanaSigner =
            requireNotNull(signer) { "signer(...) is required before configuring a protocol" }
    }

    companion object {
        private const val DEFAULT_COMPUTE_UNIT_LIMIT = 200_000
        private const val DEFAULT_COMPUTE_UNIT_PRICE = 1L

        /**
         * DSL entry point mirroring ``OkHttpClient.Builder``: configure the
         * builder in [block] and build.
         *
         * ```kotlin
         * val client = PayKitClient.httpClient {
         *     signer(signer)
         *     x402(rpcBlockhashProvider = { rpc.fetchRecentBlockhash() })
         * }
         * ```
         */
        inline fun httpClient(block: Builder.() -> Unit): PayKitClient =
            Builder().apply(block).build()
    }
}
