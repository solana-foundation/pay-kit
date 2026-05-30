package com.solana.paykit.paycore

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Base58Test {
    @Test
    fun roundTripsEmptyInput() {
        assertEquals("", Base58.encode(ByteArray(0)))
        assertContentEquals(ByteArray(0), Base58.decode(""))
    }

    @Test
    fun encodesAndDecodesSingleZeroByteAsOne() {
        val zero = byteArrayOf(0x00)
        assertEquals("1", Base58.encode(zero))
        assertContentEquals(zero, Base58.decode("1"))
    }

    @Test
    fun preservesLeadingZeroBytes() {
        val payload = byteArrayOf(0x00, 0x00, 0x00, 0x2a)
        val encoded = Base58.encode(payload)
        assertEquals("111", encoded.take(3))
        assertContentEquals(payload, Base58.decode(encoded))
    }

    @Test
    fun matchesBitcoinAlphabetVectors() {
        // Vectors from the Bitcoin Core unit suite, also matched by Solana
        // canonical helpers and the Ruby reference base58.rb.
        val cases = mapOf(
            "Hello World!" to "2NEpo7TZRRrLZSi2U",
            "The quick brown fox jumps over the lazy dog." to
                "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z",
            "" to "",
        )
        for ((plain, expected) in cases) {
            val bytes = plain.encodeToByteArray()
            assertEquals(expected, Base58.encode(bytes), "encode($plain)")
            assertContentEquals(bytes, Base58.decode(expected), "decode($expected)")
        }
    }

    @Test
    fun roundTripsThirtyTwoByteSolanaPublicKey() {
        // Random-looking 32 byte payload; the actual content does not matter,
        // only that encode/decode is lossless for the canonical Solana key
        // length.
        val payload = ByteArray(32) { (it * 7 xor 0x53).toByte() }
        val encoded = Base58.encode(payload)
        assertContentEquals(payload, Base58.decode(encoded))
    }

    @Test
    fun roundTripsSixtyFourByteSolanaSignature() {
        val payload = ByteArray(64) { (255 - it).toByte() }
        val encoded = Base58.encode(payload)
        assertContentEquals(payload, Base58.decode(encoded))
    }

    @Test
    fun matchesKnownSystemProgramAddress() {
        // 11111111111111111111111111111111 is the Solana System Program id.
        // Decoded it is the all-zero 32 byte array.
        val systemProgram = "11111111111111111111111111111111"
        val decoded = Base58.decode(systemProgram)

        assertEquals(32, decoded.size)
        assertContentEquals(ByteArray(32), decoded)
        assertEquals(systemProgram, Base58.encode(decoded))
    }

    @Test
    fun rejectsCharactersOutsideTheBitcoinAlphabet() {
        assertFailsWith<MppException.InvalidBase58> { Base58.decode("0OIl") }
    }
}
