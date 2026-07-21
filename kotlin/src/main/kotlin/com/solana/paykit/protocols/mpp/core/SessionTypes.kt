package com.solana.paykit.protocols.mpp.core

import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.PaymentChannels
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.nullable
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNames
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * MPP payment-channel session wire types, mirroring the Rust spine
 * (`rust/crates/mpp/src/protocol/intents/session.rs`) and the Go reference
 * tag-for-tag and key-for-key. JSON keys are camelCase; `salt` and `recentSlot`
 * serialize as decimal strings (read string-or-number);
 * `VoucherData.cumulativeAmount` also reads the legacy `cumulative` alias;
 * `SessionAction` is an internally-tagged union flattened onto the `action` key
 * (handled by [SessionActionCodec]).
 */

/** Default voucher/session expiry: 2100-01-01T00:00:00Z (under JS max-safe-int). */
const val DEFAULT_SESSION_EXPIRES_AT: Long = 4_102_444_800L

@Serializable
enum class SessionMode {
    @SerialName("push") PUSH,
    @SerialName("pull") PULL,
}

@Serializable
enum class SessionPullVoucherStrategy {
    @SerialName("clientVoucher") CLIENT_VOUCHER,
    @SerialName("operatedVoucher") OPERATED_VOUCHER,
}

@Serializable
enum class SessionSettlementAuthority {
    @SerialName("clientVoucher") CLIENT_VOUCHER,
    @SerialName("delegated") DELEGATED,
}

@Serializable
enum class CommitStatus {
    @SerialName("committed") COMMITTED,
    @SerialName("replayed") REPLAYED,
}

/** Serializes a nullable u64 (salt/recentSlot) as a decimal string; reads string or number. */
object SaltStringSerializer : KSerializer<ULong?> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Salt", PrimitiveKind.STRING).nullable

    override fun serialize(encoder: Encoder, value: ULong?) {
        if (value == null) encoder.encodeNull() else encoder.encodeString(value.toString())
    }

    override fun deserialize(decoder: Decoder): ULong? {
        val input = decoder as? JsonDecoder
            ?: return decoder.decodeString().toULongOrNull()
                ?: throw MppException.InvalidJson()
        return when (val element = input.decodeJsonElement()) {
            is JsonNull -> null
            is JsonPrimitive ->
                // Read the raw content as ULong for both the string and number
                // forms: a u64 salt above Long.MAX_VALUE (about half the range)
                // would be lost via longOrNull when sent as a JSON number.
                element.content.toULongOrNull() ?: throw MppException.InvalidJson()
            else -> throw MppException.InvalidJson()
        }
    }
}

@Serializable
data class SessionSplit(val recipient: String, val bps: Int)

@Serializable
data class SessionRequest(
    val cap: String,
    val currency: String,
    val decimals: Int? = null,
    val network: String? = null,
    val operator: String,
    val recipient: String,
    val splits: List<SessionSplit> = emptyList(),
    val programId: String? = null,
    val description: String? = null,
    val externalId: String? = null,
    val minVoucherDelta: String? = null,
    val modes: List<SessionMode> = emptyList(),
    val pullVoucherStrategy: SessionPullVoucherStrategy? = null,
    val settlementAuthority: SessionSettlementAuthority = SessionSettlementAuthority.CLIENT_VOUCHER,
    val recentBlockhash: String? = null,
    /** Server-prefetched current slot; the program's `open_slot` PDA seed the client echoes on open. */
    @Serializable(with = SaltStringSerializer::class) val recentSlot: ULong? = null,
)

@Serializable
data class OpenPayload(
    val mode: SessionMode,
    val channelId: String? = null,
    val deposit: String? = null,
    val payer: String? = null,
    val payee: String? = null,
    val mint: String? = null,
    @Serializable(with = SaltStringSerializer::class) val salt: ULong? = null,
    val gracePeriod: Long? = null,
    /** The program's `open_slot` channel PDA seed; the server re-derives and persists it. */
    @Serializable(with = SaltStringSerializer::class) val recentSlot: ULong? = null,
    val transaction: String? = null,
    val tokenAccount: String? = null,
    val approvedAmount: String? = null,
    val owner: String? = null,
    val initMultiDelegateTx: String? = null,
    val updateDelegationTx: String? = null,
    val authorizedSigner: String,
    val signature: String,
) {
    companion object {
        fun paymentChannel(
            mode: SessionMode,
            channelId: String,
            deposit: String,
            payer: String,
            payee: String,
            mint: String,
            salt: ULong,
            gracePeriod: UInt,
            recentSlot: ULong,
            authorizedSigner: String,
            signature: String,
        ): OpenPayload = OpenPayload(
            mode = mode, channelId = channelId, deposit = deposit, payer = payer, payee = payee,
            mint = mint, salt = salt, gracePeriod = gracePeriod.toLong(), recentSlot = recentSlot,
            authorizedSigner = authorizedSigner, signature = signature,
        )

        fun push(channelId: String, deposit: String, authorizedSigner: String, signature: String): OpenPayload =
            OpenPayload(
                mode = SessionMode.PUSH, channelId = channelId, deposit = deposit,
                authorizedSigner = authorizedSigner, signature = signature,
            )

        fun pull(
            tokenAccount: String,
            approvedAmount: String,
            owner: String,
            authorizedSigner: String,
            signature: String,
        ): OpenPayload = OpenPayload(
            mode = SessionMode.PULL, tokenAccount = tokenAccount, approvedAmount = approvedAmount,
            owner = owner, authorizedSigner = authorizedSigner, signature = signature,
        )
    }

    /** Attach the server/operator-broadcast open transaction (base64). */
    fun withTransaction(transaction: String): OpenPayload = copy(transaction = transaction)
}

@Serializable
data class VoucherData(
    val channelId: String,
    @SerialName("cumulativeAmount") @JsonNames("cumulative") val cumulative: String,
    val expiresAt: Long,
    val nonce: Long? = null,
) {
    /** The 50-byte magic-prefixed Ed25519 preimage for this voucher. */
    fun messageBytes(): ByteArray {
        val amount = cumulative.toULongOrNull()
            ?: throw MppException.InvalidTransaction("invalid voucher cumulative: $cumulative")
        return PaymentChannels.voucherMessageBytes(channelId, amount, expiresAt)
    }
}

@Serializable
data class SignedVoucher(val data: VoucherData, val signature: String)

@Serializable
data class VoucherPayload(val voucher: SignedVoucher)

@Serializable
data class CommitPayload(val deliveryId: String, val voucher: SignedVoucher)

@Serializable
data class TopUpPayload(val channelId: String, val newDeposit: String, val signature: String)

@Serializable
data class ClosePayload(val channelId: String, val voucher: SignedVoucher? = null)

@Serializable
data class MeteringDirective(
    val deliveryId: String,
    val sessionId: String,
    val amount: String,
    val currency: String,
    val sequence: Long,
    val expiresAt: Long,
    val commitUrl: String? = null,
    val proof: String? = null,
) {
    /** Parse `amount` as base units. */
    fun amountBaseUnits(): ULong =
        amount.toULongOrNull() ?: throw MppException.InvalidTransaction("invalid metering amount: $amount")
}

@Serializable
data class MeteringUsage(val deliveryId: String, val amount: String) {
    fun amountBaseUnits(): ULong =
        amount.toULongOrNull() ?: throw MppException.InvalidTransaction("invalid metering usage amount: $amount")
}

@Serializable
data class CommitReceipt(
    val deliveryId: String,
    val sessionId: String,
    val amount: String,
    val cumulative: String,
    val status: CommitStatus,
)

data class MeteredEnvelope<P>(val payload: P, val metering: MeteringDirective)

/**
 * Internally-tagged session action union. The discriminator lives on the
 * `action` key and the payload fields are flattened alongside it. The TopUp tag
 * is camelCase `topUp`. Encode/decode via [SessionActionCodec].
 */
sealed interface SessionAction {
    data class Open(val payload: OpenPayload) : SessionAction
    data class Voucher(val payload: VoucherPayload) : SessionAction
    data class Commit(val payload: CommitPayload) : SessionAction
    data class TopUp(val payload: TopUpPayload) : SessionAction
    data class Close(val payload: ClosePayload) : SessionAction
}
