package com.solana.paykit.protocols.mpp.client

import com.solana.paykit.paycore.Base58
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.Mints
import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.PaymentChannels
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.protocols.mpp.core.SessionAction
import com.solana.paykit.protocols.mpp.core.SessionMode
import com.solana.paykit.protocols.mpp.core.SessionPullVoucherStrategy
import com.solana.paykit.protocols.mpp.core.SessionRequest
import com.solana.paykit.protocols.mpp.core.SessionSplit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class SessionOpenerTest {
    private val operatorAddress = Base58.encode(ByteArray(32) { 5 })
    private val recipient = Base58.encode(ByteArray(32) { 6 })
    private val blockhash = Base58.encode(ByteArray(32) { 0x11 })

    private fun request(
        modes: List<SessionMode> = listOf(SessionMode.PULL),
        strategy: SessionPullVoucherStrategy? = SessionPullVoucherStrategy.CLIENT_VOUCHER,
        splits: List<SessionSplit> = emptyList(),
    ) = SessionRequest(
        cap = "1000000", currency = "USDC", decimals = 6, network = "localnet",
        operator = operatorAddress, recipient = recipient, splits = splits, modes = modes, pullVoucherStrategy = strategy,
    )

    private fun payerSigner() = MemorySigner.fromSeed(ByteArray(32) { 1 })
    private fun sessionSigner() = MemorySigner.fromSeed(ByteArray(32) { 2 })

    @Test
    fun buildsPullClientVoucherOpenAction() {
        val sessionSigner = sessionSigner()
        val payer = payerSigner()
        val opener = PaymentChannelSession.open(request(), payer, sessionSigner, blockhash)

        assertEquals(opener.open.channelId.toBase58(), opener.session.channelIdString())
        val open = opener.action as SessionAction.Open
        assertEquals(SessionMode.PULL, open.payload.mode)
        assertEquals(opener.open.channelId.toBase58(), open.payload.channelId)
        assertEquals(PublicKey(payer.publicKeyBytes).toBase58(), open.payload.payer)
        assertEquals(sessionSigner.address, open.payload.authorizedSigner)
        assertEquals(PENDING_SERVER_SIGNATURE, open.payload.signature)
        assertNotNull(open.payload.transaction)
        // localnet USDC resolves to the mainnet mint on the MPP charge path.
        assertEquals(Mints.USDC_MAINNET, opener.open.mint.toBase58())
        assertEquals(1_000_000uL, opener.open.deposit)
        assertEquals(PaymentChannels.DEFAULT_GRACE_PERIOD_SECONDS, opener.open.gracePeriod)
    }

    @Test
    fun appliesSessionOptions() {
        val opener = PaymentChannelSession.open(
            request(), payerSigner(), sessionSigner(), blockhash,
            PaymentChannelSessionOpenOptions(cumulative = 20uL, expiresAt = 1234L),
        )
        val voucher = opener.session.prepareIncrement(5uL)
        assertEquals("25", voucher.data.cumulative)
        assertEquals(1234L, voucher.data.expiresAt)
    }

    @Test
    fun rejectsNonPullChallenge() {
        assertFailsWith<MppException> {
            PaymentChannelSession.open(request(modes = listOf(SessionMode.PUSH), strategy = null), payerSigner(), sessionSigner(), blockhash)
        }
    }

    @Test
    fun rejectsOperatedVoucherChallenge() {
        assertFailsWith<MppException> {
            PaymentChannelSession.open(request(strategy = SessionPullVoucherStrategy.OPERATED_VOUCHER), payerSigner(), sessionSigner(), blockhash)
        }
    }

    @Test
    fun rejectsInvalidSessionSplitBpsAsMppException() {
        assertFailsWith<MppException.InvalidTransaction> {
            PaymentChannelSession.open(
                request(splits = listOf(SessionSplit(recipient = recipient, bps = 0x1_0000))),
                payerSigner(),
                sessionSigner(),
                blockhash,
            )
        }
    }
}
