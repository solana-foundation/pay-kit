package com.solana.paykit.paycore

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

/**
 * Wire-format parity tests for the Solana transaction codec.
 *
 * Golden vector source: rust/examples/golden_tx.rs (compiled against the
 * solana-message + solana-transaction + ed25519-dalek crates that the
 * Rust MPP SDK already depends on). The test reproduces the exact build
 * in Kotlin and asserts byte-for-byte equality.
 *
 *   Deterministic seed: 32 byte 0x42.
 *   Public key:         2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12
 *   Recipient:          CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY
 *   Recent blockhash:   32 zero bytes (all 1s when base58-encoded)
 *   Lamports:           1_000_000
 *   Instructions:       [SystemProgram::transfer]
 */
class TransactionTest {
    private val rustSeed = ByteArray(32) { 0x42 }
    private val rustPubkey = hex("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
    private val rustMessage = hex(
        "010001032152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12ab4e2b331e4b4f3a1542bae0f955dd5d330349c74ea1c70a9205ec06550922330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001020200010c0200000040420f0000000000",
    )
    private val rustTx = hex(
        "010e34f0d9a5a3c87737d2b746ed3d23f8ed708fea3d05d0b49e4947113f0de919750cab6da6b60e8e3a24ef9358e01e62344fac3c378a39ff479fae6ce81b190a010001032152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12ab4e2b331e4b4f3a1542bae0f955dd5d330349c74ea1c70a9205ec06550922330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001020200010c0200000040420f0000000000",
    )

    @Test
    fun legacyMessageMatchesRustGoldenVector() {
        val signer = MemorySigner.fromSeed(rustSeed)
        assertContentEquals(rustPubkey, signer.publicKeyBytes)

        val from = PublicKey(signer.publicKeyBytes)
        val to = PublicKey.fromBase58("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
        val ix = Instructions.systemTransfer(from.toBase58(), to.toBase58(), 1_000_000L)
        val message = Transaction.buildLegacyMessage(
            feePayer = from,
            recentBlockhash = ByteArray(32),
            instructions = listOf(ix),
        )

        assertContentEquals(rustMessage, message.serialize())
    }

    @Test
    fun legacyTransactionMatchesRustGoldenVector() {
        val signer = MemorySigner.fromSeed(rustSeed)
        val from = PublicKey(signer.publicKeyBytes)
        val to = PublicKey.fromBase58("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
        val ix = Instructions.systemTransfer(from.toBase58(), to.toBase58(), 1_000_000L)
        val message = Transaction.buildLegacyMessage(
            feePayer = from,
            recentBlockhash = ByteArray(32),
            instructions = listOf(ix),
        )
        val signature = signer.sign(message.serialize())
        val tx = Transaction.serializeLegacyTransaction(message, listOf(signature))

        assertContentEquals(rustTx, tx)
    }

    @Test
    fun compactU16EncodesShortLengthInOneByte() {
        assertContentEquals(byteArrayOf(0x00), Transaction.encodeCompactU16(0))
        assertContentEquals(byteArrayOf(0x01), Transaction.encodeCompactU16(1))
        assertContentEquals(byteArrayOf(0x7f), Transaction.encodeCompactU16(127))
    }

    @Test
    fun compactU16EncodesTwoByteValues() {
        // 128 = [0x80, 0x01], 16383 = [0xff, 0x7f].
        assertContentEquals(byteArrayOf(0x80.toByte(), 0x01), Transaction.encodeCompactU16(128))
        assertContentEquals(byteArrayOf(0xff.toByte(), 0x7f), Transaction.encodeCompactU16(16383))
    }

    @Test
    fun compactU16EncodesThreeByteValues() {
        // 16384 = [0x80, 0x80, 0x01], 65535 = [0xff, 0xff, 0x03].
        assertContentEquals(
            byteArrayOf(0x80.toByte(), 0x80.toByte(), 0x01),
            Transaction.encodeCompactU16(16384),
        )
        assertContentEquals(
            byteArrayOf(0xff.toByte(), 0xff.toByte(), 0x03),
            Transaction.encodeCompactU16(65535),
        )
    }

    @Test
    fun compactU16RejectsOutOfRange() {
        assertFailsWith<IllegalArgumentException> { Transaction.encodeCompactU16(65536) }
        assertFailsWith<IllegalArgumentException> { Transaction.encodeCompactU16(-1) }
    }

    @Test
    fun compactionGroupsBySignerAndWritable() {
        val payer = "5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK"
        val writableNonSigner = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        val readonlySigner = "9wZW7AKEAQiV8DSBdvLudo3SkuxBwh3KrFP1nN8ePoX8"
        val readonlyNonSigner = "8L8KXxqAdptT2vWzkAesyRwk6yJ6BPBuwzdt8nFb1ehu"

        val ix = Instruction(
            programId = Programs.MEMO_PROGRAM,
            accounts = listOf(
                AccountMeta(pubkey = readonlySigner, isSigner = true, isWritable = false),
                AccountMeta(pubkey = writableNonSigner, isSigner = false, isWritable = true),
                AccountMeta(pubkey = readonlyNonSigner, isSigner = false, isWritable = false),
            ),
            data = byteArrayOf(),
        )
        val message = Transaction.buildLegacyMessage(
            feePayer = PublicKey.fromBase58(payer),
            recentBlockhash = ByteArray(32),
            instructions = listOf(ix),
        )

        assertEquals(2, message.header.numRequiredSignatures)
        assertEquals(1, message.header.numReadonlySigned)
        // Memo program plus the read-only non-signer account; the memo
        // program is itself a read-only non-signer key.
        assertEquals(2, message.header.numReadonlyUnsigned)
        assertEquals(payer, message.accountKeys[0].toBase58())
        assertEquals(readonlySigner, message.accountKeys[1].toBase58())
        assertEquals(writableNonSigner, message.accountKeys[2].toBase58())
    }

    @Test
    fun v0MessagePrefixIsHighBitVersionZero() {
        val signer = MemorySigner.fromSeed(rustSeed)
        val from = PublicKey(signer.publicKeyBytes)
        val to = PublicKey.fromBase58("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
        val ix = Instructions.systemTransfer(from.toBase58(), to.toBase58(), 1L)
        val message = Transaction.buildV0Message(
            feePayer = from,
            recentBlockhash = ByteArray(32),
            instructions = listOf(ix),
        )
        val serialized = message.serialize()
        assertEquals(0x80.toByte(), serialized[0], "v0 message must start with 0x80 prefix")
        // Trailing byte is the (empty) address-table-lookups vector length.
        assertEquals(0x00.toByte(), serialized.last(), "v0 message must end with empty ALT vector")
    }

    @Test
    fun v0TransactionDiffersFromLegacyForSameInputs() {
        val signer = MemorySigner.fromSeed(rustSeed)
        val from = PublicKey(signer.publicKeyBytes)
        val to = PublicKey.fromBase58("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
        val ix = Instructions.systemTransfer(from.toBase58(), to.toBase58(), 1L)
        val legacy = Transaction.buildLegacyMessage(
            feePayer = from,
            recentBlockhash = ByteArray(32),
            instructions = listOf(ix),
        )
        val v0 = Transaction.buildV0Message(
            feePayer = from,
            recentBlockhash = ByteArray(32),
            instructions = listOf(ix),
        )
        val sigLegacy = signer.sign(legacy.serialize())
        val sigV0 = signer.sign(v0.serialize())
        val legacyTx = Transaction.serializeLegacyTransaction(legacy, listOf(sigLegacy))
        val v0Tx = Transaction.serializeV0Transaction(v0, listOf(sigV0))
        assertNotEquals(legacyTx.toList(), v0Tx.toList())
    }

    @Test
    fun rejectsWrongBlockhashLength() {
        val from = PublicKey.fromBase58("5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK")
        assertFailsWith<IllegalArgumentException> {
            Transaction.buildLegacyMessage(from, ByteArray(31), emptyList())
        }
    }

    @Test
    fun rejectsMismatchedSignatureCount() {
        val from = PublicKey.fromBase58("5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK")
        val ix = Instructions.systemTransfer(from.toBase58(), from.toBase58(), 0L)
        val message = Transaction.buildLegacyMessage(from, ByteArray(32), listOf(ix))
        assertFailsWith<IllegalArgumentException> {
            Transaction.serializeLegacyTransaction(message, emptyList())
        }
    }

    @Test
    fun missingSignatureSlotIsZeroPadded() {
        val from = PublicKey.fromBase58("5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK")
        val ix = Instructions.systemTransfer(from.toBase58(), from.toBase58(), 0L)
        val message = Transaction.buildLegacyMessage(from, ByteArray(32), listOf(ix))
        val serialized = Transaction.serializeLegacyTransaction(message, listOf(null))
        // Skip compact-u16 prefix (1 byte for a one signature slot).
        val signatureBytes = serialized.copyOfRange(1, 1 + 64)
        assertContentEquals(ByteArray(64), signatureBytes)
    }

    @Test
    fun legacyMessageEqualsAndHashCodeAreContentBased() {
        val from = PublicKey.fromBase58("5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK")
        val ix = Instructions.systemTransfer(from.toBase58(), from.toBase58(), 1L)
        val a = Transaction.buildLegacyMessage(from, ByteArray(32), listOf(ix))
        val b = Transaction.buildLegacyMessage(from, ByteArray(32), listOf(ix))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, Transaction.buildLegacyMessage(from, ByteArray(32) { 1 }, listOf(ix)))
    }

    @Test
    fun v0MessageEqualsAndHashCodeAreContentBased() {
        val from = PublicKey.fromBase58("5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK")
        val ix = Instructions.systemTransfer(from.toBase58(), from.toBase58(), 1L)
        val a = Transaction.buildV0Message(from, ByteArray(32), listOf(ix))
        val b = Transaction.buildV0Message(from, ByteArray(32), listOf(ix))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun compiledInstructionEqualsAndHashCodeAreContentBased() {
        val a = Transaction.CompiledInstruction(0, byteArrayOf(1, 2), byteArrayOf(3))
        val b = Transaction.CompiledInstruction(0, byteArrayOf(1, 2), byteArrayOf(3))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, Transaction.CompiledInstruction(1, byteArrayOf(1, 2), byteArrayOf(3)))
    }

    @Test
    fun rejectsWrongLengthSignatureBytes() {
        val from = PublicKey.fromBase58("5xX4f7yqg3DV8oQiTpkH5dyP5kBTb6oC7B4FmCe3wYMK")
        val ix = Instructions.systemTransfer(from.toBase58(), from.toBase58(), 0L)
        val message = Transaction.buildLegacyMessage(from, ByteArray(32), listOf(ix))
        assertFailsWith<IllegalArgumentException> {
            Transaction.serializeLegacyTransaction(message, listOf(ByteArray(63)))
        }
        val v0 = Transaction.buildV0Message(from, ByteArray(32), listOf(ix))
        assertFailsWith<IllegalArgumentException> {
            Transaction.serializeV0Transaction(v0, listOf(ByteArray(65)))
        }
        assertFailsWith<IllegalArgumentException> {
            Transaction.serializeV0Transaction(v0, emptyList())
        }
        assertFailsWith<IllegalArgumentException> {
            Transaction.buildV0Message(from, ByteArray(31), listOf(ix))
        }
    }

    private fun hex(value: String): ByteArray {
        val clean = value.replace("\\s".toRegex(), "")
        require(clean.length % 2 == 0)
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(clean[2 * i], 16) shl 4)
                + Character.digit(clean[2 * i + 1], 16)).toByte()
        }
        return out
    }
}
