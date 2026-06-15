// Minimal x402 (exact scheme, Solana) client example.
//
// Source-only today: kept outside the main source set so the default
// `gradle build` stays library-only. To run locally, point a Kotlin
// application module at this file and pass:
//
//   X402_CLIENT_SECRET_KEY_HEX=<hex>  ./run <target-url>
//
// The client GETs the target; on a 402 the x402 payment interceptor parses
// the challenge, builds and signs a v0 payment transaction, and replays the
// request with the `Payment-Signature` header. Mirrors the ChargeClient example.

package com.solana.paykit.examples

import com.solana.paykit.client.PayKitClient
import com.solana.paykit.paycore.MemorySigner
import kotlinx.coroutines.runBlocking

fun main(args: Array<String>) = runBlocking {
    val target = args.firstOrNull() ?: error("usage: X402Client <url>")
    val keyHex = System.getenv("X402_CLIENT_SECRET_KEY_HEX")
        ?: error("set X402_CLIENT_SECRET_KEY_HEX")
    val secretKey = keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val signer = MemorySigner.fromSecretKey(secretKey)
    val client = PayKitClient.Builder()
        .signer(signer)
        // RPC is only consulted when an offer omits extra.recentBlockhash.
        // null network defaults to mainnet; pass "devnet" for Surfpool/devnet.
        .x402(rpc = "https://402.surfnet.dev", network = System.getenv("X402_NETWORK"))
        .build()

    val result = client.get(target)
    result.response.use { response ->
        println("status:        ${result.status}")
        if (result.paymentSent) {
            println("paid:          yes (Payment-Signature sent)")
        } else {
            println("paid:          no (server did not require payment)")
        }
        result.settlement?.let { println("settlement:    $it") }
    }
}
