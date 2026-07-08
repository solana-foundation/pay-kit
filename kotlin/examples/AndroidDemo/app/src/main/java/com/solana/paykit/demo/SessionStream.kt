package com.solana.paykit.demo

import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.SolanaSigner
import com.solana.paykit.protocols.mpp.client.CommitTransport
import com.solana.paykit.protocols.mpp.client.PaymentChannelSession
import com.solana.paykit.protocols.mpp.client.SessionConsumer
import com.solana.paykit.protocols.mpp.core.CommitPayload
import com.solana.paykit.protocols.mpp.core.CommitReceipt
import com.solana.paykit.protocols.mpp.core.MeteringDirective
import com.solana.paykit.protocols.mpp.core.MppHeaders
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.SecureRandom
import java.util.UUID

/**
 * Drives a full MPP payment-channel **session** against the playground's
 * `/api/v1/stream` (a metered SSE endpoint) — the flow the one-shot charge
 * client can't do. Mirrors the iOS `SessionStream`:
 *
 *   1. GET unauthenticated -> 402 `WWW-Authenticate` session challenge.
 *   2. Open the channel: `PaymentChannelSession.open` builds the payer-signed
 *      open tx; the credential carries it and the server (operator) co-signs +
 *      broadcasts. Retrying the GET with that credential returns the SSE stream.
 *   3. Read the SSE deliveries (`data: {chunk,cost}` ... `[DONE]`), summing cost.
 *   4. Reserve a delivery on the side channel, then sign + commit one cumulative
 *      voucher through `SessionConsumer`.
 *   5. Poll the receipt route for the on-chain settle signature.
 *
 * Synchronous (blocking OkHttp); call it off the main thread.
 */
object SessionStream {
    data class Result(
        val channelId: String,
        val chunks: Int,
        val totalPaidBaseUnits: Long,
        val cumulative: String,
        val settleSignature: String?,
        /** Ordered trace of each step's output, surfaced in the log so the flow
         *  is visible (open -> stream -> commit -> settle). */
        val steps: List<String>,
    )

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
        explicitNulls = false
    }
    private val JSON_MEDIA = "application/json".toMediaType()

    fun consume(client: OkHttpClient, streamUrl: String, payer: SolanaSigner): Result {
        val steps = mutableListOf<String>()
        // 1. Unauthenticated GET -> 402 session challenge.
        val challenge = client.newCall(
            Request.Builder().url(streamUrl).header("Accept", "application/json").get().build()
        ).execute().use { resp ->
            if (resp.code != 402) error("expected 402 from stream, got ${resp.code}")
            val header = resp.header("WWW-Authenticate") ?: error("402 had no WWW-Authenticate header")
            MppHeaders.parseWWWAuthenticate(header)
        }
        PaymentChannelSession.requireSolanaSession(challenge)
        val request = PaymentChannelSession.sessionRequest(challenge)
        val blockhash = request.recentBlockhash
        require(!blockhash.isNullOrEmpty()) { "session challenge did not carry a recentBlockhash" }
        // The server prefetches the current slot into the challenge as
        // `recentSlot`; it is the program's open_slot channel PDA seed the open
        // echoes back, only accepted within the 1500-slot open window.
        val recentSlot = request.recentSlot
        requireNotNull(recentSlot) { "session challenge did not carry a recentSlot" }

        // 2. Open the channel (pull + clientVoucher, server-broadcast).
        val sessionSigner = MemorySigner.fromSeed(randomSeed())
        val opener = PaymentChannelSession.open(request, payer, sessionSigner, blockhash, recentSlot)
        val channelId = opener.open.channelId.toBase58()
        val credential = PaymentChannelSession.serializeSessionCredential(challenge.echo(), opener.action)
        steps.add("opened channel ${shortId(channelId)} · deposit ${usd(request.cap)}")

        // 3. Retry the GET with the open credential -> 200 SSE; read deliveries.
        var chunks = 0
        var total = 0L
        client.newCall(
            Request.Builder().url(streamUrl)
                .header("Authorization", credential)
                .header("Accept", "text/event-stream")
                .get().build()
        ).execute().use { resp ->
            if (!resp.isSuccessful) error("stream open failed: HTTP ${resp.code}")
            val reader = resp.body?.charStream()?.buffered() ?: error("stream had no body")
            while (true) {
                val line = reader.readLine() ?: break
                if (!line.startsWith("data:")) continue
                val payload = line.removePrefix("data:").trim()
                if (payload == "[DONE]") break
                val obj = runCatching { json.parseToJsonElement(payload).jsonObject }.getOrNull() ?: continue
                chunks++
                (obj["cost"] as? JsonPrimitive)?.contentOrNull?.toLongOrNull()?.let { total += it }
            }
        }
        steps.add("streamed $chunks chunks · metered ${usd(total)}")

        // 4. Reserve one aggregate delivery, then sign + commit the voucher.
        var cumulative = "0"
        if (total > 0) {
            val directive = reserveDelivery(client, sideChannel(streamUrl, "/__402/session/deliveries"), channelId, total, streamUrl)
            val consumer = SessionConsumer(opener.session, HttpCommitTransport(client, sideChannel(streamUrl, "/__402/session/commit")))
            val receipt = consumer.commitDirective(directive)
            cumulative = receipt.cumulative
            steps.add("committed voucher · cumulative ${receipt.cumulative} (${receipt.status.name.lowercase()})")
        }

        // 5. Best-effort receipt poll for the settle signature.
        val settle = runCatching { pollReceipt(client, sideChannel(streamUrl, "/sessions/receipt/$channelId")) }.getOrNull()
        steps.add(if (settle != null) "settled on-chain · ${shortId(settle)}" else "settle pending (idle-close runs server-side)")

        return Result(channelId, chunks, total, cumulative, settle, steps)
    }

    private fun shortId(value: String): String =
        if (value.length > 14) "${value.take(6)}…${value.takeLast(6)}" else value

    private fun usd(baseUnits: Long): String =
        "$" + java.math.BigDecimal(baseUnits).divide(java.math.BigDecimal(1_000_000)).stripTrailingZeros().toPlainString()

    private fun usd(baseUnitsString: String): String =
        baseUnitsString.toLongOrNull()?.let { usd(it) } ?: baseUnitsString

    private fun reserveDelivery(
        client: OkHttpClient,
        url: String,
        channelId: String,
        amount: Long,
        commitUrl: String,
    ): MeteringDirective {
        val body = buildJsonObject {
            put("amount", amount.toString())
            put("sessionId", channelId)
            put("deliveryId", "mpp-${UUID.randomUUID()}")
            put("commitUrl", commitUrl)
        }
        val req = Request.Builder().url(url)
            .header("Accept", "application/json")
            .post(json.encodeToString(JsonObject.serializer(), body).toRequestBody(JSON_MEDIA))
            .build()
        return client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) error("delivery reservation failed: HTTP ${resp.code}")
            json.decodeFromString(MeteringDirective.serializer(), resp.body!!.string())
        }
    }

    private fun pollReceipt(client: OkHttpClient, url: String): String? {
        repeat(8) {
            Thread.sleep(1_500)
            val obj = client.newCall(Request.Builder().url(url).get().build()).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                runCatching { json.parseToJsonElement(resp.body!!.string()).jsonObject }.getOrNull()
            } ?: return@repeat
            // The program renamed finalize -> seal; accept both receipt keys
            // while the playground still serves the legacy `finalized` flag.
            val sealed = (obj["sealed"] as? JsonPrimitive)?.contentOrNull == "true" ||
                (obj["finalized"] as? JsonPrimitive)?.contentOrNull == "true"
            val sig = (obj["settledSignature"] as? JsonPrimitive)?.contentOrNull
            if (sealed && !sig.isNullOrEmpty()) return sig
        }
        return null
    }

    private fun sideChannel(streamUrl: String, path: String): String =
        streamUrl.toHttpUrl().newBuilder().encodedPath(path).query(null).build().toString()

    private fun randomSeed(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }
}

/** Posts signed vouchers to `POST /__402/session/commit` and decodes the receipt. */
private class HttpCommitTransport(
    private val client: OkHttpClient,
    private val commitUrl: String,
) : CommitTransport {
    private val json = Json { encodeDefaults = false; explicitNulls = false; ignoreUnknownKeys = true }
    private val media = "application/json".toMediaType()

    override fun commit(directive: MeteringDirective, payload: CommitPayload): CommitReceipt {
        val req = Request.Builder().url(commitUrl)
            .header("Accept", "application/json")
            .post(json.encodeToString(CommitPayload.serializer(), payload).toRequestBody(media))
            .build()
        return client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                throw MppException.InvalidTransaction(
                    "voucher commit failed: HTTP ${resp.code} ${resp.body?.string().orEmpty()}"
                )
            }
            json.decodeFromString(CommitReceipt.serializer(), resp.body!!.string())
        }
    }
}
