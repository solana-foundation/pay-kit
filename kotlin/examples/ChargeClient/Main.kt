// Minimal charge-client example.
//
// Source-only today: kept outside the main source set so the default
// `gradle build` stays library-only. To run locally, point a Kotlin
// application module at this file and pass:
//
//   MPP_CLIENT_SECRET_KEY_HEX=<hex>  ./run <target-url>

package com.solana.mpp.examples

import com.solana.mpp.client.Charge
import com.solana.mpp.client.JsonRpcClient
import com.solana.mpp.client.MppHttpClient
import com.solana.mpp.crypto.MemorySigner

fun main(args: Array<String>) {
    val target = args.firstOrNull() ?: error("usage: ChargeClient <url>")
    val keyHex = System.getenv("MPP_CLIENT_SECRET_KEY_HEX")
        ?: error("set MPP_CLIENT_SECRET_KEY_HEX")
    val secretKey = keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val signer = MemorySigner.fromSecretKey(secretKey)
    val rpc = JsonRpcClient("https://402.surfnet.dev")
    val client = MppHttpClient(signer = signer, blockhashProvider = rpc)

    val response = client.mppGet(target)
    println("status:    ${response.code}")
    response.header("Payment-Receipt")?.let { println("signature: $it") }
    println("intent:    ${Charge::class.simpleName}")
}
