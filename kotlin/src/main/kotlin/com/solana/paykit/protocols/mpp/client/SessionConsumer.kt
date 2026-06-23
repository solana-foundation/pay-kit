package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.MppException
import com.solana.paykit.protocols.mpp.core.CommitPayload
import com.solana.paykit.protocols.mpp.core.CommitReceipt
import com.solana.paykit.protocols.mpp.core.CommitStatus
import com.solana.paykit.protocols.mpp.core.MeteredEnvelope
import com.solana.paykit.protocols.mpp.core.MeteringDirective

/** Transport that commits a signed voucher to the session server and returns a receipt. */
fun interface CommitTransport {
    fun commit(directive: MeteringDirective, payload: CommitPayload): CommitReceipt
}

/**
 * Client side of metered delivery: signs a voucher per directive, commits it
 * through the transport, and advances the local watermark only on success.
 * Mirrors Go `SessionConsumer`.
 */
class SessionConsumer(val session: ActiveSession, val transport: CommitTransport) {
    /** Validate the directive against the active session and wrap it for ack. */
    fun <P> accept(envelope: MeteredEnvelope<P>): MeteredDelivery<P> {
        validateDirective(envelope.metering)
        return MeteredDelivery(this, envelope.payload, envelope.metering)
    }

    /**
     * Sign a voucher for the directive amount, commit it, and advance the
     * watermark. Rejects a mismatched session, a non-integer amount, or a zero
     * amount before committing. On a committed receipt the prepared voucher is
     * recorded; on a replayed receipt the watermark reconciles to the settled
     * cumulative, clamped to the just-prepared voucher (server untrusted) and
     * never regressing.
     */
    fun commitDirective(directive: MeteringDirective): CommitReceipt {
        validateDirective(directive)
        val amount = directive.amountBaseUnits()
        if (amount == 0uL) {
            throw MppException.InvalidTransaction("metered delivery amount must be greater than zero")
        }

        val voucher = session.prepareIncrement(amount)
        val payload = CommitPayload(directive.deliveryId, voucher)
        val receipt = transport.commit(directive, payload)

        when (receipt.status) {
            CommitStatus.REPLAYED -> {
                val settled = receipt.cumulative.toULongOrNull()
                    ?: throw MppException.InvalidTransaction("invalid replayed receipt cumulative: ${receipt.cumulative}")
                val prepared = voucher.data.cumulative.toULongOrNull()
                    ?: throw MppException.InvalidTransaction("invalid prepared voucher cumulative: ${voucher.data.cumulative}")
                session.reconcileSettled(minOf(settled, prepared))
            }
            CommitStatus.COMMITTED -> session.recordVoucher(voucher)
        }
        return receipt
    }

    private fun validateDirective(directive: MeteringDirective) {
        val channelId = session.channelIdString()
        if (directive.sessionId != channelId) {
            throw MppException.InvalidTransaction(
                "metered delivery session ${directive.sessionId} does not match active session $channelId"
            )
        }
    }
}

/**
 * A validated metered delivery awaiting acknowledgement. `ack`/`commit` sign and
 * commit the voucher; `intoParts` releases the payload without committing.
 */
class MeteredDelivery<P>(
    private val consumer: SessionConsumer,
    val payload: P,
    val metering: MeteringDirective,
) {
    fun ack(): CommitReceipt = consumer.commitDirective(metering)

    fun commit(): CommitReceipt = ack()

    fun intoParts(): Pair<P, MeteringDirective> = payload to metering
}
