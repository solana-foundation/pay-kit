// Minimal charge-client example.
//
// Source-only today: kept outside the main source set so the default
// `gradle build` stays library-only. To run locally, point a Kotlin
// application module at this file and pass:
//
//   MPP_CLIENT_SECRET_KEY_HEX=<hex>  ./run <target-url>

package com.solana.paykit.examples

import com.solana.paykit.client.PayKitClient
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.protocols.mpp.client.JsonRpcClient
import kotlinx.coroutines.runBlocking

fun main(args: Array<String>) = runBlocking {
    val target = args.firstOrNull() ?: error("usage: ChargeClient <url>")
    val keyHex = System.getenv("MPP_CLIENT_SECRET_KEY_HEX")
        ?: error("set MPP_CLIENT_SECRET_KEY_HEX")
    val secretKey = keyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    val signer = MemorySigner.fromSecretKey(secretKey)
    val client = PayKitClient.Builder()
        .signer(signer)
        .charge(blockhashProvider = JsonRpcClient("https://402.surfnet.dev"))
        .build()

    val result = client.get(target)
    result.response.use {
        println("status:    ${result.status}")
        result.settlement?.let { sig -> println("signature: $sig") }
    }
}
