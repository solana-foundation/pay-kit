package org.solana.x402.exact

import com.google.gson.JsonObject
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SolanaTransactionTest {
    @Test
    fun `base58 round trips public keys`() {
        val key = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
        assertEquals(key, SolanaPublicKey.fromBase58(key).base58)
    }

    @Test
    fun `derives canonical associated token accounts`() {
        val mint = SolanaPublicKey.fromBase58("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
        val tokenProgram = SolanaPublicKey.fromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

        val source = associatedTokenAddress(
            owner = SolanaPublicKey.fromBase58("11111111111111111111111111111112"),
            mint = mint,
            tokenProgram = tokenProgram,
        )
        val destination = associatedTokenAddress(
            owner = SolanaPublicKey.fromBase58("11111111111111111111111111111115"),
            mint = mint,
            tokenProgram = tokenProgram,
        )

        assertEquals("4tRapEGgJZKuGoeeMRrpHsxAEuvo5YnDCzTXykqDhrK9", source.base58)
        assertEquals("CFGbKktYnf4cVvvkVYXPCFfHKq6TE7zc9XdBKxqS5P4q", destination.base58)
    }

    @Test
    fun `default builder creates partially signed exact transaction shape`() {
        val accepted = JsonObject().apply {
            addProperty("scheme", "exact")
            addProperty("network", ExactChallenge.DEFAULT_NETWORK)
            addProperty("asset", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
            addProperty("amount", "1000")
            addProperty("payTo", "11111111111111111111111111111115")
            add(
                "extra",
                JsonObject().apply {
                    addProperty("feePayer", "11111111111111111111111111111111")
                    addProperty("decimals", 6)
                    addProperty("tokenProgram", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                    addProperty("memo", "order-123")
                },
            )
        }
        val request = SolanaExactPaymentRequest(
            payer = "11111111111111111111111111111112",
            network = ExactChallenge.DEFAULT_NETWORK,
            asset = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            amount = "1000",
            payTo = "11111111111111111111111111111115",
            feePayer = "11111111111111111111111111111111",
            memo = "order-123",
            maxTimeoutSeconds = 60,
            accepted = accepted,
        )

        val tx = DefaultSolanaExactTransactionBuilder(FixedRpc).buildUnsignedTransaction(request)

        assertEquals(2, tx.signatures.size)
        assertEquals(1, tx.signerIndex)
        assertEquals(0x80, tx.message[0].toInt() and 0xff)
        assertEquals(2, tx.message[1].toInt())
        assertContentEquals(ByteArray(64), tx.signatures[0])
    }

    @Test
    fun `compileV0Message dedupes accounts that appear in multiple instructions with different roles`() {
        // Regression for Greptile P2: independent role sets used to allow the same
        // pubkey to be emitted twice in accountKeys when two instructions reference
        // it under different (signer, writable) classifications. The cross-set
        // dedup now promotes to the strongest role and emits the key once.
        val feePayer = SolanaPublicKey.fromBase58("11111111111111111111111111111111")
        val payer = SolanaPublicKey.fromBase58("11111111111111111111111111111112")
        val shared = SolanaPublicKey.fromBase58("11111111111111111111111111111115")
        val program = SolanaPublicKey.fromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

        // Instruction 1: shared is read-only, non-signer.
        // Instruction 2: shared is writable, non-signer.
        // Expected: shared appears exactly once, promoted to writable non-signer.
        val instructions = listOf(
            SolanaInstruction(
                programId = program,
                accounts = listOf(AccountMeta(shared, signer = false, writable = false)),
                data = byteArrayOf(1),
            ),
            SolanaInstruction(
                programId = program,
                accounts = listOf(AccountMeta(shared, signer = false, writable = true)),
                data = byteArrayOf(2),
            ),
        )

        val compiled = SolanaTransactionCodec.compileV0Message(
            feePayer = feePayer,
            signers = listOf(feePayer, payer),
            instructions = instructions,
            recentBlockhash = SolanaPublicKey.fromBase58("11111111111111111111111111111111"),
        )

        assertEquals(
            compiled.accountKeys.size,
            compiled.accountKeys.toSet().size,
            "accountKeys must contain no duplicates",
        )
        assertEquals(1, compiled.accountKeys.count { it == shared })
        // shared must be in the writable-non-signer slice, i.e. after the
        // signer slices (feePayer + payer = 2) but before the read-only-non-signers.
        val sharedIndex = compiled.accountKeys.indexOf(shared)
        assertTrue(sharedIndex >= compiled.requiredSignatures, "shared promoted to writable should follow signers")
    }

    @Test
    fun `builder rejects amounts above signed-u64 range`() {
        // Regression for the dead `amount <= ULong.MAX_VALUE` guard. The real
        // hazard is the downstream Long narrowing — values above Long.MAX_VALUE
        // must be rejected explicitly rather than silently producing a negative
        // Long and corrupting the transferChecked payload.
        val accepted = JsonObject().apply {
            addProperty("scheme", "exact")
            addProperty("network", ExactChallenge.DEFAULT_NETWORK)
            addProperty("asset", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
            addProperty("amount", "1")
            addProperty("payTo", "11111111111111111111111111111115")
            add(
                "extra",
                JsonObject().apply {
                    addProperty("feePayer", "11111111111111111111111111111111")
                    addProperty("decimals", 6)
                    addProperty("tokenProgram", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
                },
            )
        }
        val boundary = (Long.MAX_VALUE.toULong() + 1u).toString()
        val request = SolanaExactPaymentRequest(
            payer = "11111111111111111111111111111112",
            network = ExactChallenge.DEFAULT_NETWORK,
            asset = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            amount = boundary,
            payTo = "11111111111111111111111111111115",
            feePayer = "11111111111111111111111111111111",
            memo = null,
            maxTimeoutSeconds = 60,
            accepted = accepted,
        )

        val error = assertFailsWith<IllegalArgumentException> {
            DefaultSolanaExactTransactionBuilder(FixedRpc).buildUnsignedTransaction(request)
        }
        assertTrue(
            error.message?.contains("signed-u64", ignoreCase = true) == true,
            "expected signed-u64 overflow guard, got: ${error.message}",
        )
    }

    @Test
    fun `transferChecked_rejects_unsupported_program`() {
        // P1 security: builder is a public entry point. If accepted.tokenProgram
        // (or RPC owner) ever points at an arbitrary program, fail loudly
        // before serializing transferChecked into the message.
        val accepted = JsonObject().apply {
            addProperty("scheme", "exact")
            addProperty("network", ExactChallenge.DEFAULT_NETWORK)
            addProperty("asset", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
            addProperty("amount", "1")
            addProperty("payTo", "11111111111111111111111111111115")
            addProperty("tokenProgram", "EvilProgram1111111111111111111111111111")
            add(
                "extra",
                JsonObject().apply {
                    addProperty("feePayer", "11111111111111111111111111111111")
                    addProperty("decimals", 6)
                },
            )
        }
        val request = SolanaExactPaymentRequest(
            payer = "11111111111111111111111111111112",
            network = ExactChallenge.DEFAULT_NETWORK,
            asset = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            amount = "1",
            payTo = "11111111111111111111111111111115",
            feePayer = "11111111111111111111111111111111",
            memo = null,
            maxTimeoutSeconds = 60,
            accepted = accepted,
        )
        val error = assertFailsWith<IllegalArgumentException> {
            DefaultSolanaExactTransactionBuilder(FixedRpc).buildUnsignedTransaction(request)
        }
        assertTrue(
            error.message?.contains("unsupported tokenProgram") == true,
            "expected unsupported-tokenProgram rejection, got: ${error.message}",
        )
    }

    @Test
    fun `transferChecked_rejects_unsupported_program_from_rpc_owner`() {
        // Even if the server omits tokenProgram entirely, the RPC metadata
        // owner is untrusted data — must also be on the SPL allowlist.
        val accepted = JsonObject().apply {
            addProperty("scheme", "exact")
            addProperty("network", ExactChallenge.DEFAULT_NETWORK)
            addProperty("asset", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
            addProperty("amount", "1")
            addProperty("payTo", "11111111111111111111111111111115")
            add(
                "extra",
                JsonObject().apply {
                    addProperty("feePayer", "11111111111111111111111111111111")
                    addProperty("decimals", 6)
                },
            )
        }
        val request = SolanaExactPaymentRequest(
            payer = "11111111111111111111111111111112",
            network = ExactChallenge.DEFAULT_NETWORK,
            asset = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            amount = "1",
            payTo = "11111111111111111111111111111115",
            feePayer = "11111111111111111111111111111111",
            memo = null,
            maxTimeoutSeconds = 60,
            accepted = accepted,
        )
        val hostileRpc = object : SolanaRpc {
            override fun latestBlockhash(): String = "11111111111111111111111111111111"
            override fun tokenMetadata(mint: String): SolanaTokenMetadata =
                SolanaTokenMetadata(
                    tokenProgram = "EvilProgram1111111111111111111111111111",
                    decimals = 6,
                )
        }
        val error = assertFailsWith<IllegalArgumentException> {
            DefaultSolanaExactTransactionBuilder(hostileRpc).buildUnsignedTransaction(request)
        }
        assertTrue(
            error.message?.contains("unsupported tokenProgram") == true,
            "expected unsupported-tokenProgram rejection, got: ${error.message}",
        )
    }

    @Test
    fun `transferChecked_accepts_token_2022_program`() {
        val accepted = JsonObject().apply {
            addProperty("scheme", "exact")
            addProperty("network", ExactChallenge.DEFAULT_NETWORK)
            addProperty("asset", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
            addProperty("amount", "1000")
            addProperty("payTo", "11111111111111111111111111111115")
            add(
                "extra",
                JsonObject().apply {
                    addProperty("feePayer", "11111111111111111111111111111111")
                    addProperty("decimals", 6)
                    addProperty("tokenProgram", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
                },
            )
        }
        val request = SolanaExactPaymentRequest(
            payer = "11111111111111111111111111111112",
            network = ExactChallenge.DEFAULT_NETWORK,
            asset = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            amount = "1000",
            payTo = "11111111111111111111111111111115",
            feePayer = "11111111111111111111111111111111",
            memo = null,
            maxTimeoutSeconds = 60,
            accepted = accepted,
        )
        val tx = DefaultSolanaExactTransactionBuilder(FixedRpc).buildUnsignedTransaction(request)
        assertEquals(2, tx.signatures.size)
    }
}

private object FixedRpc : SolanaRpc {
    override fun latestBlockhash(): String = "11111111111111111111111111111111"

    override fun tokenMetadata(mint: String): SolanaTokenMetadata =
        SolanaTokenMetadata(
            tokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            decimals = 6,
        )
}
