// Minimal x402 (exact scheme, Solana) client example.
//
// Source-only today: kept outside the main source set so the default
// `gradle build` stays library-only. To run locally, point a Kotlin
// application module at this file and pass:
//
//   X402_CLIENT_SECRET_KEY_HEX=<hex>  ./run <target-url>
//
// The client GETs the target; on a 402 it parses the x402 challenge, builds
// and signs a v0 payment transaction, and replays the request with the
// `Payment-Signature` header. Mirrors the ChargeClient example.

package com.solana.mpp.examples

import com.solana.mpp._paycore.MemorySigner
import com.solana.mpp.protocols.x402.client.exact.ChallengeSelection
import com.solana.mpp.protocols.x402.client.exact.X402HttpClient
import com.solana.mpp.protocols.x402.client.exact.X402RpcClient

fun main(args: Array<String>) {
    val target = args.firstOrNull() ?: error("usage: X402Client <url>")
    val keyHex = System.getenv("X402_CLIENT_SECRET_KEY_HEX")
        ?: error("set X402_CLIENT_SECRET_KEY_HEX")
    val secretKey = keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val signer = MemorySigner.fromSecretKey(secretKey)
    // RPC is only consulted when an offer omits extra.recentBlockhash.
    val rpc = X402RpcClient("https://402.surfnet.dev")
    val client = X402HttpClient(
        signer = signer,
        rpcBlockhashProvider = { rpc.fetchRecentBlockhash() },
        // null network defaults to mainnet; pass "devnet" for Surfpool/devnet.
        selection = ChallengeSelection(network = System.getenv("X402_NETWORK")),
    )

    val result = client.get(target)
    result.response.use { response ->
        println("status:        ${response.code}")
        result.paymentSignatureSent?.let { println("paid:          yes (Payment-Signature sent)") }
            ?: println("paid:          no (server did not require payment)")
        response.header("x-fixture-settlement")?.let { println("settlement:    $it") }
    }
}
