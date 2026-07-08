package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.Base64Url
import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.PaymentChannels
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.paycore.SolanaSigner
import com.solana.paykit.paycore.defaultTokenProgramForCurrency
import com.solana.paykit.paycore.resolveStablecoinMint
import com.solana.paykit.protocols.mpp.core.CanonicalJson
import com.solana.paykit.protocols.mpp.core.ChallengeEcho
import com.solana.paykit.protocols.mpp.core.ClosePayload
import com.solana.paykit.protocols.mpp.core.DEFAULT_SESSION_EXPIRES_AT
import com.solana.paykit.protocols.mpp.core.MppHeaders
import com.solana.paykit.protocols.mpp.core.OpenPayload
import com.solana.paykit.protocols.mpp.core.PaymentChallenge
import com.solana.paykit.protocols.mpp.core.SessionAction
import com.solana.paykit.protocols.mpp.core.SessionActionCodec
import com.solana.paykit.protocols.mpp.core.SessionMode
import com.solana.paykit.protocols.mpp.core.SessionPullVoucherStrategy
import com.solana.paykit.protocols.mpp.core.SessionRequest
import com.solana.paykit.protocols.mpp.core.SignedVoucher
import com.solana.paykit.protocols.mpp.core.TopUpPayload
import com.solana.paykit.protocols.mpp.core.VoucherData
import com.solana.paykit.protocols.mpp.core.VoucherPayload
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement

/**
 * A live metered session bound to one payment channel.
 *
 * Holds the cumulative watermark, request nonce, and voucher expiry, and signs
 * monotonically-increasing vouchers with the session signer. Mirrors the Go
 * reference `ActiveSession` including the `ReconcileSettled` lost-response
 * clamp. Sessions are single-threaded (not thread-safe), matching Rust `&mut`.
 */
class ActiveSession(
    val channelId: String,
    private val signer: SolanaSigner,
    cumulative: ULong = 0uL,
    expiresAt: Long = DEFAULT_SESSION_EXPIRES_AT,
) {
    var cumulative: ULong = cumulative
        private set
    var nonce: ULong = 0uL
        private set
    var expiresAt: Long = expiresAt
        private set

    fun setExpiresAt(value: Long) {
        expiresAt = value
    }

    /** base58 of the session signer's public key (the on-chain authorized signer). */
    fun authorizedSigner(): String = signer.address

    fun channelIdString(): String = channelId

    // ── Voucher signing ──

    /** Sign a voucher at an absolute cumulative without advancing the watermark. */
    fun prepareVoucher(cumulative: ULong): SignedVoucher {
        if (cumulative <= this.cumulative) {
            throw MppException.InvalidTransaction(
                "voucher cumulative $cumulative must exceed current watermark ${this.cumulative}"
            )
        }
        val data = VoucherData(
            channelId = channelId,
            cumulative = cumulative.toString(),
            expiresAt = expiresAt,
            nonce = (nonce + 1uL).toLong(),
        )
        val signature = signer.sign(data.messageBytes())
        return SignedVoucher(data, Base58.encode(signature))
    }

    fun prepareIncrement(amount: ULong): SignedVoucher = prepareVoucher(addToWatermark(amount))

    /**
     * Advance the watermark to a recorded voucher: rejects a voucher bound to a
     * different channel, a non-increasing cumulative, or an unparseable
     * cumulative; advances the nonce to at least `nonce + 1` (or the voucher's
     * nonce when higher). Mirrors Go `RecordVoucher`.
     */
    fun recordVoucher(voucher: SignedVoucher) {
        if (voucher.data.channelId != channelIdString()) {
            throw MppException.InvalidTransaction(
                "voucher channel ${voucher.data.channelId} does not match active session ${channelIdString()}"
            )
        }
        val cumulative = voucher.data.cumulative.toULongOrNull()
            ?: throw MppException.InvalidTransaction("invalid voucher cumulative")
        if (cumulative <= this.cumulative) {
            throw MppException.InvalidTransaction(
                "voucher cumulative $cumulative must exceed current watermark ${this.cumulative}"
            )
        }
        this.cumulative = cumulative
        var candidate = this.nonce + 1uL
        val voucherNonce = voucher.data.nonce?.toULong()
        if (voucherNonce != null && voucherNonce > candidate) candidate = voucherNonce
        this.nonce = candidate
    }

    /**
     * Reconcile the watermark to a server-settled cumulative (e.g. a replayed
     * commit receipt): advance only when ahead, never regress, bump the nonce on
     * advance. Mirrors Go `ReconcileSettled` (the #162 lost-response fix).
     */
    fun reconcileSettled(settled: ULong) {
        if (settled > cumulative) {
            cumulative = settled
            nonce += 1uL
        }
    }

    fun signVoucher(cumulative: ULong): SignedVoucher {
        val voucher = prepareVoucher(cumulative)
        recordVoucher(voucher)
        return voucher
    }

    fun signIncrement(amount: ULong): SignedVoucher = signVoucher(addToWatermark(amount))

    // ── Action builders ──

    fun voucherAction(amount: ULong): SessionAction = SessionAction.Voucher(VoucherPayload(signIncrement(amount)))

    /** Cooperative close; a `finalIncrement` > 0 signs one last voucher first. */
    fun closeAction(finalIncrement: ULong?): SessionAction {
        val voucher = if (finalIncrement != null && finalIncrement > 0uL) signIncrement(finalIncrement) else null
        return SessionAction.Close(ClosePayload(channelId, voucher))
    }

    fun openAction(deposit: ULong, openTxSignature: String): SessionAction =
        SessionAction.Open(OpenPayload.push(channelId, deposit.toString(), authorizedSigner(), openTxSignature))

    fun openPaymentChannelAction(
        mode: SessionMode = SessionMode.PUSH,
        deposit: ULong,
        payer: String,
        payee: String,
        mint: String,
        salt: ULong,
        gracePeriod: UInt,
        signature: String,
    ): SessionAction = SessionAction.Open(
        OpenPayload.paymentChannel(
            mode, channelId, deposit.toString(), payer, payee, mint, salt, gracePeriod, authorizedSigner(), signature
        )
    )

    /**
     * Build a pull-mode (SPL delegation) open action. The channel ID is used as
     * the token account, so callers should construct the [ActiveSession] with
     * the delegated token account pubkey as the channel ID. Mirrors Go
     * `OpenPullAction` and Rust `open_pull_action`.
     */
    fun openPullAction(approvedAmount: ULong, owner: String, approveTxSignature: String): SessionAction =
        SessionAction.Open(OpenPayload.pull(channelId, approvedAmount.toString(), owner, authorizedSigner(), approveTxSignature))

    fun topupAction(newDeposit: ULong, topupTxSignature: String): SessionAction =
        SessionAction.TopUp(TopUpPayload(channelId, newDeposit.toString(), topupTxSignature))

    private fun addToWatermark(amount: ULong): ULong {
        val sum = cumulative + amount
        if (sum < cumulative) {
            throw MppException.InvalidTransaction("voucher cumulative overflow adding $amount to $cumulative")
        }
        return sum
    }
}

// ── Payment-channel session opener ──

/** Placeholder operator signature; the server fills its fee-payer slot before broadcast. */
const val PENDING_SERVER_SIGNATURE: String =
    "1111111111111111111111111111111111111111111111111111111111111111"

/** Derived channel parameters for an open. */
data class PaymentChannelOpen(
    val channelId: PublicKey,
    val payer: PublicKey,
    val payee: PublicKey,
    val mint: PublicKey,
    val authorizedSigner: PublicKey,
    val salt: ULong,
    val deposit: ULong,
    val gracePeriod: UInt,
    val recipients: List<PaymentChannels.Distribution>,
    val tokenProgram: PublicKey,
    val programId: PublicKey,
) {
    fun openPayload(mode: SessionMode, signature: String): OpenPayload =
        OpenPayload.paymentChannel(
            mode = mode,
            channelId = channelId.toBase58(),
            deposit = deposit.toString(),
            payer = payer.toBase58(),
            payee = payee.toBase58(),
            mint = mint.toBase58(),
            salt = salt,
            gracePeriod = gracePeriod,
            authorizedSigner = authorizedSigner.toBase58(),
            signature = signature,
        )
}

/** Per-channel open overrides; unset fields fall back to challenge-derived defaults. */
data class PaymentChannelOpenOptions(
    val deposit: ULong? = null,
    val gracePeriod: UInt? = null,
    val programId: PublicKey? = null,
    val recipients: List<PaymentChannels.Distribution>? = null,
    val salt: ULong? = null,
    val tokenProgram: PublicKey? = null,
)

data class PaymentChannelSessionOpenOptions(
    val open: PaymentChannelOpenOptions = PaymentChannelOpenOptions(),
    val signature: String? = null,
    val cumulative: ULong? = null,
    val expiresAt: Long? = null,
)

/** Result of opening a payment-channel session client-side. */
data class PaymentChannelSessionOpen(
    val open: PaymentChannelOpen,
    val session: ActiveSession,
    val action: SessionAction,
)

object PaymentChannelSession {
    private val json = Json {
        encodeDefaults = false
        explicitNulls = false
        ignoreUnknownKeys = true
    }

    /**
     * Build a pull + clientVoucher payment-channel session open. The payer
     * partial-signs the open transaction; the operator (fee payer) co-signs and
     * broadcasts. `recentBlockhash` is base58. Mirrors
     * `create_payment_channel_session_opener`.
     */
    fun open(
        request: SessionRequest,
        payerSigner: SolanaSigner,
        sessionSigner: SolanaSigner,
        recentBlockhash: String,
        options: PaymentChannelSessionOpenOptions = PaymentChannelSessionOpenOptions(),
    ): PaymentChannelSessionOpen {
        ensureClientVoucherPull(request)
        val authorizedSigner = PublicKey(sessionSigner.publicKeyBytes)
        val feePayer = PublicKey.fromBase58(request.operator)
        val payer = PublicKey(payerSigner.publicKeyBytes)
        val open = deriveOpen(request, payer, authorizedSigner, options.open)

        val blockhash = Base58.decode(recentBlockhash)
        if (blockhash.size != 32) {
            throw MppException.InvalidTransaction("recentBlockhash must decode to 32 bytes")
        }
        val tx = PaymentChannels.buildOpenTransaction(
            payer = payerSigner,
            payee = open.payee,
            mint = open.mint,
            authorizedSigner = open.authorizedSigner,
            salt = open.salt,
            deposit = open.deposit,
            gracePeriod = open.gracePeriod,
            recipients = open.recipients,
            tokenProgram = open.tokenProgram,
            programId = open.programId,
            feePayer = feePayer,
            recentBlockhash = blockhash,
        )

        val session = ActiveSession(
            channelId = open.channelId.toBase58(),
            signer = sessionSigner,
            cumulative = options.cumulative ?: 0uL,
            expiresAt = options.expiresAt ?: DEFAULT_SESSION_EXPIRES_AT,
        )
        val signature = options.signature ?: PENDING_SERVER_SIGNATURE
        val action = SessionAction.Open(open.openPayload(SessionMode.PULL, signature).withTransaction(tx.transaction))
        return PaymentChannelSessionOpen(open, session, action)
    }

    private fun ensureClientVoucherPull(request: SessionRequest) {
        if (!request.modes.contains(SessionMode.PULL)) {
            throw MppException.InvalidTransaction("session challenge does not advertise pull mode")
        }
        if (request.pullVoucherStrategy != SessionPullVoucherStrategy.CLIENT_VOUCHER) {
            throw MppException.InvalidTransaction("session challenge does not advertise pull + clientVoucher")
        }
    }

    private fun deriveOpen(
        request: SessionRequest,
        payer: PublicKey,
        authorizedSigner: PublicKey,
        options: PaymentChannelOpenOptions,
    ): PaymentChannelOpen {
        val mintString = resolveStablecoinMint(request.currency, request.network)
            ?: throw MppException.InvalidTransaction("session payment channels require an SPL token")
        val mint = PublicKey.fromBase58(mintString)
        val payee = PublicKey.fromBase58(request.recipient)
        val deposit = options.deposit
            ?: request.cap.toULongOrNull()
            ?: throw MppException.InvalidTransaction("invalid session cap: ${request.cap}")
        val gracePeriod = options.gracePeriod ?: PaymentChannels.DEFAULT_GRACE_PERIOD_SECONDS
        val programId = options.programId
            ?: request.programId?.let { PublicKey.fromBase58(it) }
            ?: PublicKey.fromBase58(PaymentChannels.PROGRAM_ID)
        val tokenProgram = options.tokenProgram
            ?: PublicKey.fromBase58(defaultTokenProgramForCurrency(request.currency, request.network))
        val recipients = options.recipients
            ?: request.splits.map {
                try {
                    PaymentChannels.Distribution(PublicKey.fromBase58(it.recipient), it.bps)
                } catch (error: IllegalArgumentException) {
                    throw MppException.InvalidTransaction("invalid session split: ${error.message}")
                }
            }
        val salt = options.salt ?: PaymentChannels.uniqueSalt()
        val channelId = PaymentChannels.findChannelPda(payer, payee, mint, authorizedSigner, salt, programId)
        return PaymentChannelOpen(
            channelId = channelId, payer = payer, payee = payee, mint = mint, authorizedSigner = authorizedSigner,
            salt = salt, deposit = deposit, gracePeriod = gracePeriod, recipients = recipients,
            tokenProgram = tokenProgram, programId = programId,
        )
    }

    /**
     * Build an `Authorization: Payment <base64url(JCS(credential))>` value for a
     * session action, echoing the challenge. Mirrors Go `SerializeSessionCredential`.
     */
    fun serializeSessionCredential(challenge: ChallengeEcho, action: SessionAction): String {
        val tree = buildJsonObject {
            put("challenge", json.encodeToJsonElement(ChallengeEcho.serializer(), challenge))
            put("payload", SessionActionCodec.toJsonObject(action))
        }
        val canonical = CanonicalJson.encode(tree)
        return "${MppHeaders.PAYMENT_SCHEME} ${Base64Url.encode(canonical.encodeToByteArray())}"
    }

    /** Decode the base64url-encoded session request carried by a challenge. */
    fun sessionRequest(challenge: PaymentChallenge): SessionRequest {
        if (challenge.request.length > MppHeaders.MAX_TOKEN_LEN) {
            throw MppException.InvalidHeader
        }
        return try {
            json.decodeFromString(SessionRequest.serializer(), Base64Url.decode(challenge.request).decodeToString())
        } catch (error: IllegalArgumentException) {
            throw MppException.InvalidJson(error)
        } catch (error: kotlinx.serialization.SerializationException) {
            throw MppException.InvalidJson(error)
        }
    }

    /** Require a `solana`/`session` challenge before opening a session. */
    fun requireSolanaSession(challenge: PaymentChallenge) {
        if (challenge.method != "solana" || challenge.intent != "session") {
            throw MppException.UnsupportedChallenge(challenge.method, challenge.intent)
        }
    }
}
