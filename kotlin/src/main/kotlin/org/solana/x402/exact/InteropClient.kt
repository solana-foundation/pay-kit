package org.solana.x402.exact

import java.net.HttpURLConnection
import java.net.URI

fun main() {
    val targetUrl = System.getenv("X402_INTEROP_TARGET_URL")

    if (targetUrl.isNullOrBlank()) {
        println(
            ExactChallenge.resultJson(
                ok = false,
                status = 0,
                error = "X402_INTEROP_TARGET_URL is required",
            ),
        )
        return
    }

    try {
        val signer = MemorySolanaTransactionSigner.fromJsonByteArray(
            System.getenv("X402_INTEROP_CLIENT_SECRET_KEY")
                ?: throw IllegalArgumentException("X402_INTEROP_CLIENT_SECRET_KEY is required"),
        )
        val rpc = JsonRpcSolanaClient(
            System.getenv("X402_INTEROP_RPC_URL")
                ?: throw IllegalArgumentException("X402_INTEROP_RPC_URL is required"),
        )
        val paymentClient = ExactPaymentClient(DefaultSolanaExactTransactionBuilder(rpc), signer)

        val firstResponse = get(targetUrl)
        val selected = ExactChallenge.selectSvmChallenge(
            headers = firstResponse.headers,
            body = firstResponse.body,
            network = System.getenv("X402_INTEROP_NETWORK") ?: ExactChallenge.DEFAULT_NETWORK,
            scheme = System.getenv("X402_INTEROP_SCHEME") ?: "exact",
            preferredCurrencies = System.getenv("X402_INTEROP_PREFER_CURRENCIES")
                ?.split(",")
                ?.map { it.trim() }
                ?.filter { it.isNotEmpty() }
                ?: emptyList(),
        )

        if (selected == null) {
            println(
                ExactChallenge.resultJson(
                    ok = false,
                    status = firstResponse.status,
                    responseHeaders = firstResponse.headers,
                    responseBody = firstResponse.body,
                    error = "No supported Solana exact payment requirement was found",
                ),
            )
            return
        }

        val headers = paymentClient.createPaymentHeaders(selected, signer.publicKey.base58)
        val paidResponse = get(targetUrl, headers)
        println(
            ExactChallenge.resultJson(
                ok = paidResponse.status in 200..299,
                status = paidResponse.status,
                responseHeaders = paidResponse.headers,
                responseBody = parseBody(paidResponse.body),
                settlement = paidResponse.headers.entries
                    .firstOrNull { it.key.equals("x-fixture-settlement", ignoreCase = true) }
                    ?.value,
            ),
        )
    } catch (error: Throwable) {
        println(
            ExactChallenge.resultJson(
                ok = false,
                status = 0,
                error = error.message ?: error.toString(),
            ),
        )
    }
}

private fun parseBody(body: String): Any? {
    if (body.isBlank()) {
        return null
    }
    return try {
        com.google.gson.JsonParser.parseString(body)
    } catch (_: RuntimeException) {
        body
    }
}

private data class HttpResponse(
    val status: Int,
    val headers: Map<String, String>,
    val body: String,
)

private fun get(url: String, headers: Map<String, String> = emptyMap()): HttpResponse {
    val connection = URI(url).toURL().openConnection() as HttpURLConnection
    connection.requestMethod = "GET"
    connection.connectTimeout = 10_000
    connection.readTimeout = 10_000
    headers.forEach { (name, value) -> connection.setRequestProperty(name, value) }

    val status = connection.responseCode
    val stream = if (status >= 400) connection.errorStream else connection.inputStream
    val body = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
    val responseHeaders = connection.headerFields
        .filterKeys { it != null }
        .mapValues { (_, values) -> values.joinToString(",") }

    return HttpResponse(status, responseHeaders, body)
}
