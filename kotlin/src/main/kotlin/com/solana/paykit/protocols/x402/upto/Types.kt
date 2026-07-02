package com.solana.paykit.protocols.x402.upto

import com.solana.paykit.paycore.SolanaNetwork
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonElement

/**
 * x402 ``upto`` wire shapes (payment-channel asset transfer method).
 *
 * ``upto`` authorizes a maximum amount: the client opens an on-chain payment
 * channel whose deposit is the ceiling, with the operator (facilitator) as the
 * channel payee, authorized signer, fee payer, and rent payer. The operator
 * later settles the metered amount with a single voucher and refunds the
 * remainder. The client signs only its payer slot of the ``open`` transaction.
 */

/** ``upto`` scheme identifier. */
const val UPTO_SCHEME: String = "upto"

/** Payment-channel asset transfer method (the only SVM ``upto`` backend). */
const val UPTO_ASSET_TRANSFER_METHOD: String = "payment-channel"

/** The ``extra`` object on an ``upto`` requirement. */
@Serializable
data class UptoExtra(
    /** Asset transfer method; MUST equal ``payment-channel`` for the SVM backend. */
    val assetTransferMethod: String,
    /** Token program address; defaults to the legacy SPL Token program when absent. */
    val tokenProgram: String? = null,
    /** Base58 operator key: channel payee, authorized signer, fee payer, and settler. */
    val facilitatorAddress: String? = null,
    /** Operator cut in basis points (0..10000) of the settled amount; omitted when 0. */
    val facilitatorFee: Int = 0,
    /** Channel program id; defaults to the canonical deployment when absent. */
    val channelProgram: String? = null,
    /** Server-prefetched recent blockhash for building the open transaction. */
    val recentBlockhash: String? = null,
    /** Last block height at which ``recentBlockhash`` is valid (decimal string). */
    val lastValidBlockHeight: String? = null,
    /** Earliest activation time (Unix seconds). */
    val validAfter: Long? = null,
)

/** An ``upto`` payment requirement (one ``accepts[]`` entry in a 402 challenge). */
@Serializable
data class UptoRequirements(
    /** Scheme identifier; ``upto`` for this requirement. Always emitted so the
     *  server reads it from the echoed ``accepted`` object. */
    @EncodeDefault(EncodeDefault.Mode.ALWAYS)
    val scheme: String = UPTO_SCHEME,
    /** CAIP-2 network identifier; unknown networks parse as [SolanaNetwork.Other]. */
    val network: SolanaNetwork,
    /** Maximum authorized amount in base units (decimal string). */
    val amount: String,
    /** SPL mint address. */
    val asset: String,
    /** Base58 beneficiary recipient. */
    val payTo: String,
    /** Completion window in seconds. */
    val maxTimeoutSeconds: Long,
    /** Scheme-specific data. */
    val extra: UptoExtra,
    /**
     * Verbatim offered object as received on the wire, echoed back unchanged in
     * the ``Payment-Signature`` envelope's ``accepted`` field so server-specific
     * fields the typed properties do not model survive the round trip. ``null``
     * for requirements built in code; populated during parsing.
     */
    @Transient val raw: JsonElement? = null,
)

/** The ``PAYMENT-REQUIRED`` envelope for an ``upto`` challenge. */
@Serializable
data class UptoRequiredEnvelope(
    /** x402 protocol version. */
    val x402Version: Int,
    /** Advertised payment requirements. */
    val accepts: List<UptoRequirements> = emptyList(),
    /** Optional human-readable error from the server. */
    val error: String? = null,
)

/**
 * The client authorization carried in ``PAYMENT-SIGNATURE.payload``.
 *
 * For the payment-channel method the channel ``open`` is the authorization: the
 * client's signature commits the deposit ceiling, payee, and mint. There is no
 * ``signature`` or ``profile`` field; the operator settles with its own voucher.
 */
@Serializable
data class UptoPayload(
    /** Payer wallet (base58). */
    val from: String,
    /** Signed ceiling in base units; MUST equal the verification-phase amount. */
    val maxAmount: String,
    /** Deadline (Unix seconds) signed into the on-chain voucher. */
    val expiresAt: Long,
    /** Activation time (Unix seconds). */
    val validAfter: Long,
    /** Unique per-authorization identifier. */
    val nonce: String,
    /** Channel PDA (base58). */
    val channelId: String,
    /** On-chain escrow ceiling in base units; MUST equal ``maxAmount``. */
    val deposit: String,
    /** Voucher signer: the operator/facilitator key (base58). */
    val authorizedSigner: String,
    /** Base64 client-signed ``open`` transaction for the operator to co-sign and broadcast. */
    val openTransaction: String? = null,
)

/** The ``PAYMENT-SIGNATURE`` envelope for an ``upto`` payment. */
@Serializable
data class UptoSignatureEnvelope(
    /** x402 protocol version. */
    val x402Version: Int,
    /** The chosen requirements object, opaque JSON; carries ``scheme`` and ``network``. */
    val accepted: JsonElement,
    /** The client authorization payload. */
    val payload: UptoPayload,
)

/** The ``PAYMENT-RESPONSE`` settlement result for an ``upto`` payment. */
@Serializable
data class UptoSettlementResponse(
    /** Whether settlement succeeded. */
    val success: Boolean,
    /** Reason for failure when ``success`` is false. */
    val errorReason: String? = null,
    /** Payer wallet (base58) the operator settled against. */
    val payer: String? = null,
    /** Settlement transaction signature; absent on a failure response. */
    val transaction: String? = null,
    /** CAIP-2 network identifier; absent on a generic failure response. */
    val network: SolanaNetwork? = null,
    /** Actual base units charged (may be ``0``); absent on a failure response. */
    val amount: String? = null,
)
