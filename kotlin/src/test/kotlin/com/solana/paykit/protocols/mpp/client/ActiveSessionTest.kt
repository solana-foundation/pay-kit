package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.protocols.mpp.core.DEFAULT_SESSION_EXPIRES_AT
import com.solana.paykit.protocols.mpp.core.SessionAction
import com.solana.paykit.protocols.mpp.core.SessionMode
import com.solana.paykit.protocols.mpp.core.SignedVoucher
import com.solana.paykit.protocols.mpp.core.VoucherData
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ActiveSessionTest {
    private fun session(seed: Byte = 42, channel: Byte = 7): ActiveSession {
        val signer = MemorySigner.fromSeed(ByteArray(32) { seed })
        return ActiveSession(PublicKey(ByteArray(32) { channel }).toBase58(), signer)
    }

    @Test
    fun prepareDoesNotAdvanceButRecordDoes() {
        val session = session()
        val prepared = session.prepareIncrement(75uL)
        assertEquals("75", prepared.data.cumulative)
        assertEquals(1L, prepared.data.nonce)
        assertEquals(0uL, session.cumulative)

        session.recordVoucher(prepared)
        assertEquals(75uL, session.cumulative)
        assertFailsWith<MppException> { session.recordVoucher(prepared) }
    }

    @Test
    fun signIncrementAdvancesWatermarkAndNonce() {
        val session = session()
        val first = session.signIncrement(100uL)
        assertEquals("100", first.data.cumulative)
        assertEquals(1L, first.data.nonce)
        assertEquals(100uL, session.cumulative)

        val second = session.signIncrement(10uL)
        assertEquals("110", second.data.cumulative)
        assertEquals(2L, second.data.nonce)
        assertEquals(110uL, session.cumulative)
    }

    @Test
    fun signVoucherRejectsNonIncreasingAndZero() {
        val session = session()
        session.signIncrement(100uL)
        assertFailsWith<MppException> { session.signVoucher(100uL) }
        assertFailsWith<MppException> { session.signVoucher(50uL) }
        assertFailsWith<MppException> { session(seed = 9, channel = 8).signVoucher(0uL) }
    }

    @Test
    fun recordVoucherRejectsInvalidCumulativeAndDefaultsNonce() {
        val session = session()
        val bad = SignedVoucher(VoucherData(session.channelIdString(), "not-a-number", DEFAULT_SESSION_EXPIRES_AT), "sig")
        assertFailsWith<MppException> { session.recordVoucher(bad) }

        val noNonce = SignedVoucher(VoucherData(session.channelIdString(), "15", DEFAULT_SESSION_EXPIRES_AT, null), "sig")
        session.recordVoucher(noNonce)
        assertEquals(15uL, session.cumulative)
        assertEquals(1uL, session.nonce)
    }

    @Test
    fun recordVoucherRejectsForeignChannel() {
        val session = session()
        val foreign = SignedVoucher(VoucherData("11111111111111111111111111111112", "10", DEFAULT_SESSION_EXPIRES_AT), "sig")
        assertFailsWith<MppException> { session.recordVoucher(foreign) }
        assertEquals(0uL, session.cumulative)
    }

    @Test
    fun reconcileSettledAdvancesAndNeverRegresses() {
        val session = session()
        session.reconcileSettled(300uL)
        assertEquals(300uL, session.cumulative)
        session.reconcileSettled(100uL)
        assertEquals(300uL, session.cumulative)
    }

    @Test
    fun expiresAtControlsVoucherExpiry() {
        val session = session()
        session.setExpiresAt(1234L)
        assertEquals(1234L, session.prepareIncrement(10uL).data.expiresAt)
        session.setExpiresAt(5678L)
        assertEquals(5678L, session.prepareIncrement(10uL).data.expiresAt)
    }

    @Test
    fun closeActionVoucherFollowsFinalIncrement() {
        val session = session()
        val emptyClose = session.closeAction(null) as SessionAction.Close
        assertNull(emptyClose.payload.voucher)

        session.signIncrement(100uL)
        val close = session.closeAction(50uL) as SessionAction.Close
        assertEquals("150", close.payload.voucher?.data?.cumulative)

        val zeroClose = session.closeAction(0uL) as SessionAction.Close
        assertNull(zeroClose.payload.voucher)
    }

    @Test
    fun openTopupAndPullActionFields() {
        val session = session()
        val open = session.openAction(1_000_000uL, "txsig123") as SessionAction.Open
        assertEquals(SessionMode.PUSH, open.payload.mode)
        assertEquals("1000000", open.payload.deposit)
        assertEquals("txsig123", open.payload.signature)
        assertEquals(session.channelIdString(), open.payload.channelId)
        assertEquals(session.authorizedSigner(), open.payload.authorizedSigner)

        val pull = session.openPullAction(5_000_000uL, "wallet123", "approvesig") as SessionAction.Open
        assertEquals(SessionMode.PULL, pull.payload.mode)
        assertEquals("5000000", pull.payload.approvedAmount)
        assertEquals("wallet123", pull.payload.owner)
        assertEquals(session.channelIdString(), pull.payload.tokenAccount)
        assertNull(pull.payload.channelId)

        val topUp = session.topupAction(5_000_000uL, "topuptx") as SessionAction.TopUp
        assertEquals("5000000", topUp.payload.newDeposit)
        assertEquals("topuptx", topUp.payload.signature)
        assertEquals(session.channelIdString(), topUp.payload.channelId)
    }
}
