package com.solana.mpp

import java.math.BigInteger

/**
 * Bitcoin-alphabet Base58 helpers used by Solana public keys, signatures, and
 * any other on-chain identifier that ships as a 32 or 64 byte value.
 *
 * Pure Kotlin, no JNI. The encoded form is byte-for-byte identical to the
 * Ruby `Mpp::Methods::Solana::Base58` reference at
 * `ruby/lib/mpp/methods/solana/base58.rb` and to `bs58` / `solana-sdk`
 * output on the other reference SDKs.
 */
object Base58 {
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val ALPHABET_INDEX: IntArray = IntArray(128) { -1 }.also { table ->
        for (i in ALPHABET.indices) {
            table[ALPHABET[i].code] = i
        }
    }
    private val FIFTY_EIGHT = BigInteger.valueOf(58)

    /** Encodes binary bytes as a Base58 string. */
    fun encode(binary: ByteArray): String {
        if (binary.isEmpty()) return ""

        var leadingZeros = 0
        while (leadingZeros < binary.size && binary[leadingZeros] == 0.toByte()) {
            leadingZeros += 1
        }

        var value = BigInteger(1, binary)
        val builder = StringBuilder()
        while (value.signum() > 0) {
            val (quotient, remainder) = value.divideAndRemainder(FIFTY_EIGHT)
            builder.append(ALPHABET[remainder.toInt()])
            value = quotient
        }
        repeat(leadingZeros) { builder.append(ALPHABET[0]) }

        return builder.reverse().toString()
    }

    /**
     * Decodes a Base58 string into binary bytes.
     *
     * Throws [MppException.InvalidBase58] for any character outside the
     * Bitcoin alphabet.
     */
    fun decode(value: String): ByteArray {
        if (value.isEmpty()) return ByteArray(0)

        var leadingOnes = 0
        while (leadingOnes < value.length && value[leadingOnes] == ALPHABET[0]) {
            leadingOnes += 1
        }

        var accumulator = BigInteger.ZERO
        for (character in value) {
            val code = character.code
            val index = if (code in 0..127) ALPHABET_INDEX[code] else -1
            if (index < 0) {
                throw MppException.InvalidBase58(character)
            }
            accumulator = accumulator.multiply(FIFTY_EIGHT).add(BigInteger.valueOf(index.toLong()))
        }

        val magnitude = accumulator.toByteArray()
        // BigInteger.toByteArray() may prepend a sign byte for unsigned values;
        // strip it so the leading-zero accounting below stays exact.
        val stripped = if (magnitude.isNotEmpty() && magnitude[0] == 0.toByte()) {
            magnitude.copyOfRange(1, magnitude.size)
        } else {
            magnitude
        }

        val result = ByteArray(leadingOnes + stripped.size)
        System.arraycopy(stripped, 0, result, leadingOnes, stripped.size)
        return result
    }
}
