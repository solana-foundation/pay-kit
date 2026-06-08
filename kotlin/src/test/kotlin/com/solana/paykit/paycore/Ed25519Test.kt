package com.solana.paykit.paycore

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Ed25519Test {
    /**
     * RFC 8032 Test 1 vector (https://datatracker.ietf.org/doc/html/rfc8032#section-7.1).
     * Provides a deterministic seed -> public key -> signature triple that
     * any conformant Ed25519 implementation must reproduce byte-for-byte.
     */
    private val rfc8032Seed = hex(
        "9d61b19deffd5a60ba844af492ec2cc4" +
            "4449c5697b326919703bac031cae7f60",
    )
    private val rfc8032PublicKey = hex(
        "d75a980182b10ab7d54bfed3c964073a" +
            "0ee172f3daa62325af021a68f707511a",
    )
    private val rfc8032EmptyMessageSignature = hex(
        "e5564300c360ac729086e2cc806e828a" +
            "84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46b" +
            "d25bf5f0595bbe24655141438e7a100b",
    )

    @Test
    fun matchesRfc8032Test1Vector() {
        val publicKey = Ed25519.publicKey(rfc8032Seed)
        assertContentEquals(rfc8032PublicKey, publicKey)

        val signature = Ed25519.sign(rfc8032Seed, ByteArray(0))
        assertContentEquals(rfc8032EmptyMessageSignature, signature)

        assertTrue(Ed25519.verify(rfc8032PublicKey, ByteArray(0), signature))
    }

    @Test
    fun signingIsDeterministic() {
        val seed = ByteArray(32) { 0x42.toByte() }
        val message = "deterministic".encodeToByteArray()
        val first = Ed25519.sign(seed, message)
        val second = Ed25519.sign(seed, message)
        assertContentEquals(first, second)
        assertEquals(64, first.size)
    }

    @Test
    fun verifyRejectsTamperedSignature() {
        val seed = ByteArray(32) { 0x11.toByte() }
        val publicKey = Ed25519.publicKey(seed)
        val message = "tamper".encodeToByteArray()
        val signature = Ed25519.sign(seed, message).copyOf()
        signature[0] = (signature[0].toInt() xor 0x01).toByte()
        assertFalse(Ed25519.verify(publicKey, message, signature))
    }

    @Test
    fun rejectsMalformedKeyLengths() {
        assertFailsWith<IllegalArgumentException> { Ed25519.sign(ByteArray(31), ByteArray(0)) }
        assertFailsWith<IllegalArgumentException> {
            Ed25519.verify(ByteArray(31), ByteArray(0), ByteArray(64))
        }
        assertFailsWith<IllegalArgumentException> {
            Ed25519.verify(ByteArray(32), ByteArray(0), ByteArray(63))
        }
        assertFailsWith<IllegalArgumentException> { Ed25519.publicKey(ByteArray(31)) }
    }

    @Test
    fun seedFromSecretKeyAccepts32And64Bytes() {
        val seed = ByteArray(32) { it.toByte() }
        val secret = ByteArray(64).apply {
            System.arraycopy(seed, 0, this, 0, 32)
            System.arraycopy(Ed25519.publicKey(seed), 0, this, 32, 32)
        }
        assertContentEquals(seed, Ed25519.seedFromSecretKey(seed))
        assertContentEquals(seed, Ed25519.seedFromSecretKey(secret))
        assertFailsWith<IllegalArgumentException> { Ed25519.seedFromSecretKey(ByteArray(48)) }
    }

    @Test
    fun generateSeedProducesDistinctKeys() {
        val a = Ed25519.generateSeed()
        val b = Ed25519.generateSeed()
        assertEquals(32, a.size)
        assertNotEquals(a.toList(), b.toList())
    }

    private fun hex(value: String): ByteArray {
        require(value.length % 2 == 0)
        val out = ByteArray(value.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(value[2 * i], 16) shl 4)
                + Character.digit(value[2 * i + 1], 16)).toByte()
        }
        return out
    }
}
