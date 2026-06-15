package com.solana.paykit.protocols.x402.client.exact

import com.solana.paykit.paycore.AccountMeta
import com.solana.paykit.paycore.Instruction
import com.solana.programs.TokenProgram
import com.solana.publickey.SolanaPublicKey
import com.solana.transaction.TransactionInstruction
import java.math.BigInteger

/**
 * Bridge between the Solana Mobile ``web3-solana`` instruction builders and
 * the ``paycore`` instruction/transaction codec used by this client.
 *
 * web3-solana adoption (see ``build.gradle.kts``): the x402 ``exact`` client
 * builds its SPL ``transferChecked`` instruction through
 * ``com.solanamobile:web3-solana`` so the SPL wire layout (discriminator 12,
 * little-endian amount, decimals; account order source/mint/destination/
 * authority) comes from a maintained, production-used library rather than a
 * hand-rolled byte buffer.
 *
 * What web3-solana does NOT supply, and so stays hand-rolled in ``paycore``:
 *
 *  - **v0 ``VersionedMessage`` compilation.** web3-solana's ``Message.Builder``
 *    only ever produces a ``LegacyMessage``; its ``VersionedMessage`` is a bare
 *    data class with no ``try_compile`` / account-compaction path. The x402
 *    transaction MUST be v0 (the verifier reads
 *    ``static_account_keys()`` / ``instructions()`` off a versioned message),
 *    so ``paycore.Transaction.buildV0Message`` keeps doing the compaction.
 *  - **ComputeBudget.** Absent from the web3-solana jar entirely; the two
 *    ComputeBudget instructions stay in ``paycore.Instructions``.
 *  - **Associated Token Account derivation.** web3-solana only exposes a
 *    ``suspend`` ``ProgramDerivedAddress.find``; the x402 build path is
 *    synchronous, so ``paycore.Pda.associatedTokenAddress`` derives the ATAs.
 *  - **Memo / System transfer.** web3-solana's ``MemoProgram.publishMemo``
 *    adds a signer account (rust's memo has none) and its account-level shape
 *    diverges from the spine; those stay on the ``paycore`` builders that
 *    match the rust bytes.
 */
internal object Web3Solana {
    /**
     * Builds an SPL ``transferChecked`` instruction via web3-solana's
     * [TokenProgram] and lowers it into a [paycore][Instruction] for the v0
     * codec.
     *
     * web3-solana's ``transferChecked(from, to, amount, decimals, owner, mint)``
     * emits accounts ``[source(w), mint(ro), destination(w), authority(signer)]``
     * — the order the x402 verifier expects at instruction index 2.
     *
     * SPL token amounts are u64 on the wire; a signed [Long] cannot represent
     * the upper half [2^63, 2^64). web3-solana's [TokenProgram.transferChecked]
     * Borsh-encodes the amount as a raw little-endian i64, so the u64
     * bit-pattern (``BigInteger.toLong()`` two's-complement of values in
     * [2^63, 2^64)) serializes to the exact unsigned wire bytes.
     */
    fun transferChecked(
        tokenProgram: String,
        source: String,
        mint: String,
        destination: String,
        authority: String,
        amount: BigInteger,
        decimals: Int,
    ): Instruction {
        require(amount.signum() >= 0) { "amount must be non-negative" }
        require(amount < TWO_POW_64) { "amount exceeds u64 range" }
        require(decimals in 0..255) { "decimals must fit in u8" }
        val ix = TokenProgram.transferChecked(
            SolanaPublicKey.from(source),
            SolanaPublicKey.from(destination),
            // Low 64 bits as two's-complement Long == the unsigned u64 bytes.
            amount.toLong(),
            decimals.toByte(),
            SolanaPublicKey.from(authority),
            SolanaPublicKey.from(mint),
        )
        // web3-solana hard-codes the SPL Token program id. The offer may carry
        // Token-2022 instead, which shares the wire format; rebuild the
        // paycore instruction with the offer's program id so Token-2022
        // offers are honoured.
        return ix.toPaycore(programIdOverride = tokenProgram)
    }

    private val TWO_POW_64: BigInteger = BigInteger.ONE.shiftLeft(64)

    /** Lowers a web3-solana [TransactionInstruction] into a [paycore][Instruction]. */
    private fun TransactionInstruction.toPaycore(programIdOverride: String? = null): Instruction =
        Instruction(
            programId = programIdOverride ?: programId.base58(),
            accounts = accounts.map { meta ->
                AccountMeta(
                    pubkey = meta.publicKey.base58(),
                    isSigner = meta.isSigner,
                    isWritable = meta.isWritable,
                )
            },
            data = data,
        )
}
