package com.solana.paykit.paycore

import com.solana.paykit.protocols.mpp.client.ActiveSession
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Byte-exact golden vectors for the payment-channel voucher preimage and the
 * channel PDA. The preimage bytes are pinned against the frozen cross-SDK
 * conformance vector (`harness/vectors/session-voucher.json`), since Kotlin has
 * no conformance runner of its own.
 */
class SessionVoucherTest {
    // channelId base58 of 32 bytes of 0x09, matching the frozen vector.
    private val frozenChannel = "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN"

    @Test
    fun voucherPreimageMatchesFrozenVector() {
        val bytes = PaymentChannels.voucherMessageBytes(frozenChannel, 42uL, 1234L)
        val expected = ByteArray(48)
        for (i in 0..31) expected[i] = 9
        expected[32] = 42 // cumulative 42 LE u64
        expected[40] = 210.toByte() // 1234 = 0x04D2 LE i64
        expected[41] = 4
        assertTrue(bytes.contentEquals(expected))
    }

    @Test
    fun voucherPreimageNearMaxCumulativeHasNoPrecisionLoss() {
        // 18446744073709551607 = u64::MAX - 8.
        val bytes = PaymentChannels.voucherMessageBytes(frozenChannel, 18446744073709551607uL, 4102444800L)
        assertEquals(247, bytes[32].toInt() and 0xff)
        for (i in 33..39) assertEquals(255, bytes[i].toInt() and 0xff)
        // expiresAt 4102444800 = 0xF4865700 LE.
        assertEquals(0, bytes[40].toInt() and 0xff)
        assertEquals(87, bytes[41].toInt() and 0xff)
        assertEquals(134, bytes[42].toInt() and 0xff)
        assertEquals(244, bytes[43].toInt() and 0xff)
    }

    @Test
    fun channelPdaIsDeterministicAndSaltSensitive() {
        val payer = PublicKey(ByteArray(32) { 1 })
        val payee = PublicKey(ByteArray(32) { 2 })
        val mint = PublicKey(ByteArray(32) { 3 })
        val signer = PublicKey(ByteArray(32) { 4 })
        val programId = PublicKey.fromBase58(PaymentChannels.PROGRAM_ID)

        val a = PaymentChannels.findChannelPda(payer, payee, mint, signer, 99uL, programId)
        val b = PaymentChannels.findChannelPda(payer, payee, mint, signer, 99uL, programId)
        val other = PaymentChannels.findChannelPda(payer, payee, mint, signer, 100uL, programId)

        assertEquals(a, b)
        assertNotEquals(a, other)
    }

    @Test
    fun voucherSignatureVerifiesAgainstAuthorizedSigner() {
        val signer = MemorySigner.fromSeed(ByteArray(32) { 42 })
        val channel = PublicKey(ByteArray(32) { 7 }).toBase58()
        val session = ActiveSession(channel, signer)

        val voucher = session.signIncrement(100uL)
        assertTrue(Ed25519.verify(signer.publicKeyBytes, voucher.data.messageBytes(), Base58.decode(voucher.signature)))
        assertEquals(channel, voucher.data.channelId)
        assertEquals("100", voucher.data.cumulative)
    }
}
