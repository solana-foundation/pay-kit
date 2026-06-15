package com.solana.paykit.harness

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

class ParseSecretKeyTest {
    @Test
    fun acceptsValidSixtyFourByteArray() {
        val payload = "[" + (0..63).joinToString(",") + "]"
        val bytes = parseSecretKey(payload)
        assertContentEquals(ByteArray(64) { it.toByte() }, bytes)
    }

    @Test
    fun acceptsValidThirtyTwoByteArray() {
        val payload = "[" + (0..31).joinToString(",") + "]"
        val bytes = parseSecretKey(payload)
        assertContentEquals(ByteArray(32) { it.toByte() }, bytes)
    }

    @Test
    fun rejectsByteValueAboveTwoFiftyFive() {
        // 256 would silently wrap through Int.toByte() to 0 in the
        // pre-fix parser, producing a different signer with no error.
        val payload = "[" + (List(63) { it } + 256).joinToString(",") + "]"
        val error = assertFailsWith<IllegalArgumentException> { parseSecretKey(payload) }
        assertTrue(error.message!!.contains("out of range"))
        assertTrue(error.message!!.contains("256"))
    }

    @Test
    fun rejectsNegativeByteValue() {
        val payload = "[" + (List(63) { it } + -1).joinToString(",") + "]"
        val error = assertFailsWith<IllegalArgumentException> { parseSecretKey(payload) }
        assertTrue(error.message!!.contains("out of range"))
    }

    @Test
    fun rejectsWrongSize() {
        val payload = "[" + (0..15).joinToString(",") + "]"
        assertFailsWith<IllegalStateException> { parseSecretKey(payload) }
    }

    @Test
    fun rejectsNonArray() {
        assertFailsWith<IllegalStateException> { parseSecretKey("\"not-an-array\"") }
    }

    @Test
    fun rejectsNonIntegerElement() {
        val payload = "[" + (List(63) { "$it" } + "\"x\"").joinToString(",") + "]"
        assertFailsWith<IllegalStateException> { parseSecretKey(payload) }
    }

    private fun assertTrue(condition: Boolean) {
        kotlin.test.assertTrue(condition)
    }
}
