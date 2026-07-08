package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.protocols.mpp.core.CommitPayload
import com.solana.paykit.protocols.mpp.core.CommitReceipt
import com.solana.paykit.protocols.mpp.core.CommitStatus
import com.solana.paykit.protocols.mpp.core.DEFAULT_SESSION_EXPIRES_AT
import com.solana.paykit.protocols.mpp.core.MeteredEnvelope
import com.solana.paykit.protocols.mpp.core.MeteringDirective
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SessionConsumerTest {
    /** Records each commit and dedupes by deliveryId (replayed on re-commit). */
    private class RecordingTransport : CommitTransport {
        val commits = mutableListOf<CommitPayload>()
        var fail = false
        private val settled = mutableMapOf<String, String>()

        override fun commit(directive: MeteringDirective, payload: CommitPayload): CommitReceipt {
            if (fail) throw MppException.InvalidTransaction("commit failed")
            settled[directive.deliveryId]?.let { prior ->
                return CommitReceipt(directive.deliveryId, directive.sessionId, directive.amount, prior, CommitStatus.REPLAYED)
            }
            val cumulative = payload.voucher.data.cumulative
            settled[directive.deliveryId] = cumulative
            commits.add(payload)
            return CommitReceipt(directive.deliveryId, directive.sessionId, directive.amount, cumulative, CommitStatus.COMMITTED)
        }
    }

    private class ReplayTransport(val settled: String) : CommitTransport {
        override fun commit(directive: MeteringDirective, payload: CommitPayload): CommitReceipt =
            CommitReceipt(directive.deliveryId, directive.sessionId, directive.amount, settled, CommitStatus.REPLAYED)
    }

    private fun session(channel: Byte = 7): ActiveSession {
        val signer = MemorySigner.fromSeed(ByteArray(32) { 42 })
        return ActiveSession(PublicKey(ByteArray(32) { channel }).toBase58(), signer)
    }

    private fun directive(session: ActiveSession, amount: Int, deliveryId: String = "d1"): MeteringDirective =
        MeteringDirective(deliveryId, session.channelIdString(), amount.toString(), "USDC", 1L, DEFAULT_SESSION_EXPIRES_AT)

    @Test
    fun ackSendsCommitAndAdvancesWatermark() {
        val session = session()
        val transport = RecordingTransport()
        val consumer = SessionConsumer(session, transport)
        val delivery = consumer.accept(MeteredEnvelope("work", directive(session, 250)))
        assertEquals("work", delivery.payload)
        val receipt = delivery.ack()

        assertEquals("250", receipt.cumulative)
        assertEquals(CommitStatus.COMMITTED, receipt.status)
        assertEquals(250uL, session.cumulative)
        assertEquals(1, transport.commits.size)
    }

    @Test
    fun commitAliasAndIntoParts() {
        val session = session()
        session.setExpiresAt(1234L)
        val transport = RecordingTransport()
        val consumer = SessionConsumer(session, transport)

        val first = consumer.accept(MeteredEnvelope("first", directive(session, 50)))
        assertEquals("50", first.commit().cumulative)
        assertEquals(1234L, transport.commits[0].voucher.data.expiresAt)

        val second = consumer.accept(MeteredEnvelope("second", directive(session, 75, "d2")))
        val (payload, metering) = second.intoParts()
        assertEquals("second", payload)
        assertEquals("75", metering.amount)
    }

    @Test
    fun invalidDirectivesRejectedBeforeCommit() {
        val session = session()
        val transport = RecordingTransport()
        val consumer = SessionConsumer(session, transport)

        val wrong = MeteringDirective("d1", "other-session", "1", "USDC", 1L, DEFAULT_SESSION_EXPIRES_AT)
        assertFailsWith<MppException> { consumer.commitDirective(wrong) }
        assertFailsWith<MppException> { consumer.commitDirective(directive(session, 0)) }
        val badAmount = MeteringDirective("d1", session.channelIdString(), "bad", "USDC", 1L, DEFAULT_SESSION_EXPIRES_AT)
        assertFailsWith<MppException> { consumer.commitDirective(badAmount) }

        assertTrue(transport.commits.isEmpty())
        assertEquals(0uL, session.cumulative)
    }

    @Test
    fun failedCommitDoesNotAdvanceWatermark() {
        val session = session()
        val transport = RecordingTransport().apply { fail = true }
        val consumer = SessionConsumer(session, transport)

        assertFailsWith<MppException> { consumer.commitDirective(directive(session, 250)) }
        assertEquals(0uL, session.cumulative)

        transport.fail = false
        assertEquals("250", consumer.commitDirective(directive(session, 250)).cumulative)
        assertEquals(250uL, session.cumulative)
    }

    @Test
    fun duplicateDeliveryReplayDoesNotDoubleCount() {
        val session = session()
        val transport = RecordingTransport()
        val consumer = SessionConsumer(session, transport)
        val d = directive(session, 100)

        assertEquals(CommitStatus.COMMITTED, consumer.commitDirective(d).status)
        assertEquals(100uL, session.cumulative)

        val r2 = consumer.commitDirective(d)
        assertEquals(CommitStatus.REPLAYED, r2.status)
        assertEquals("100", r2.cumulative)
        assertEquals(100uL, session.cumulative)
        assertEquals(1, transport.commits.size)
    }

    @Test
    fun replayedReceiptReconcilesToClampedSettled() {
        val session = session()
        val consumer = SessionConsumer(session, ReplayTransport("100"))
        val receipt = consumer.commitDirective(directive(session, 250))
        assertEquals(CommitStatus.REPLAYED, receipt.status)
        assertEquals(100uL, session.cumulative)
    }

    @Test
    fun replayedReceiptNeverRegressesWatermark() {
        val session = session()
        session.reconcileSettled(300uL)
        val consumer = SessionConsumer(session, ReplayTransport("100"))
        consumer.commitDirective(directive(session, 50))
        assertEquals(300uL, session.cumulative)
    }

    @Test
    fun replayedReceiptClampsInflatedServerCumulative() {
        val session = session()
        val consumer = SessionConsumer(session, ReplayTransport("1000000"))
        consumer.commitDirective(directive(session, 250))
        assertEquals(250uL, session.cumulative)
    }
}
