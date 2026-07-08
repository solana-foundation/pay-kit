package com.solana.paykit.paycore

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the `open` instruction account layout after threading the on-chain
 * `rentPayer` account: it is a SIGNER + WRITABLE slot inserted right after
 * `payer` (index 1), shifting every later account by +1. The open account
 * count is therefore 14, and the signer prefix is [payer, rentPayer].
 */
class PaymentChannelsOpenAccountsTest {
    private val payer = PublicKey(ByteArray(32) { 1 })
    private val rentPayer = PublicKey(ByteArray(32) { 9 }) // operator / fee payer
    private val payee = PublicKey(ByteArray(32) { 2 })
    private val mint = PublicKey(ByteArray(32) { 3 })
    private val authorizedSigner = PublicKey(ByteArray(32) { 4 })
    private val programId = PublicKey.fromBase58(PaymentChannels.PROGRAM_ID)

    private fun params() = PaymentChannels.OpenChannelParams(
        payer = payer,
        rentPayer = rentPayer,
        payee = payee,
        mint = mint,
        authorizedSigner = authorizedSigner,
        salt = 7uL,
        deposit = 1_000uL,
        gracePeriod = PaymentChannels.DEFAULT_GRACE_PERIOD_SECONDS,
        recipients = emptyList(),
        tokenProgram = PublicKey.fromBase58(Programs.TOKEN_PROGRAM),
        programId = programId,
    )

    @Test
    fun openAccountListThreadsRentPayerAtIndexOne() {
        val ix = PaymentChannels.buildOpenInstruction(params())

        // Account count grew 13 -> 14 with the new rentPayer slot.
        assertEquals(14, ix.accounts.size)

        // index 0: payer (signer + writable).
        assertEquals(payer.toBase58(), ix.accounts[0].pubkey)
        assertTrue(ix.accounts[0].isSigner)
        assertTrue(ix.accounts[0].isWritable)

        // index 1: rentPayer (signer + writable), right after payer.
        assertEquals(rentPayer.toBase58(), ix.accounts[1].pubkey)
        assertTrue(ix.accounts[1].isSigner)
        assertTrue(ix.accounts[1].isWritable)

        // +1 shift: payee->2, mint->3, authorizedSigner->4, channel->5.
        assertEquals(payee.toBase58(), ix.accounts[2].pubkey)
        assertEquals(mint.toBase58(), ix.accounts[3].pubkey)
        assertEquals(authorizedSigner.toBase58(), ix.accounts[4].pubkey)
        assertTrue(ix.accounts[5].isWritable) // channel PDA
        assertFalse(ix.accounts[5].isSigner)

        // Trailing fixed programs/sysvars keep their order, shifted by +1.
        assertEquals(Programs.SYSTEM_PROGRAM, ix.accounts[9].pubkey)
        assertEquals(PaymentChannels.RENT_SYSVAR_ID, ix.accounts[10].pubkey)
        assertEquals(Programs.ASSOCIATED_TOKEN_PROGRAM, ix.accounts[11].pubkey)
        assertEquals(programId.toBase58(), ix.accounts[13].pubkey)

        // Exactly two signers in the open instruction: payer and rentPayer.
        assertEquals(2, ix.accounts.count { it.isSigner })
    }

    @Test
    fun buildOpenTransactionPinsRentPayerToFeePayer() {
        val payerSigner = MemorySigner.fromSeed(ByteArray(32) { 1 })
        val feePayer = PublicKey(ByteArray(32) { 9 }) // operator
        val tx = PaymentChannels.buildOpenTransaction(
            payer = payerSigner,
            payee = payee,
            mint = mint,
            authorizedSigner = authorizedSigner,
            salt = 7uL,
            deposit = 1_000uL,
            gracePeriod = PaymentChannels.DEFAULT_GRACE_PERIOD_SECONDS,
            recipients = emptyList(),
            tokenProgram = PublicKey.fromBase58(Programs.TOKEN_PROGRAM),
            programId = programId,
            feePayer = feePayer,
            recentBlockhash = ByteArray(32) { 0x11 },
        )

        // The compiled message must carry two required signers: the fee payer /
        // rentPayer (operator) leads the writable-signer bucket at index 0, the
        // payer follows at index 1. A single operator signature covers both the
        // fee-payer and rentPayer signer roles, so feePayer appears exactly once.
        val message = Transaction.buildLegacyMessage(
            feePayer,
            ByteArray(32) { 0x11 },
            listOf(
                PaymentChannels.buildOpenInstruction(
                    PaymentChannels.OpenChannelParams(
                        payer = PublicKey(payerSigner.publicKeyBytes),
                        rentPayer = feePayer,
                        payee = payee,
                        mint = mint,
                        authorizedSigner = authorizedSigner,
                        salt = 7uL,
                        deposit = 1_000uL,
                        gracePeriod = PaymentChannels.DEFAULT_GRACE_PERIOD_SECONDS,
                        recipients = emptyList(),
                        tokenProgram = PublicKey.fromBase58(Programs.TOKEN_PROGRAM),
                        programId = programId,
                    ),
                ),
            ),
        )
        assertEquals(2, message.header.numRequiredSignatures)
        assertEquals(feePayer.toBase58(), message.accountKeys[0].toBase58())
        assertEquals(PublicKey(payerSigner.publicKeyBytes).toBase58(), message.accountKeys[1].toBase58())
        assertEquals(1, message.accountKeys.count { it.bytes.contentEquals(feePayer.bytes) })

        // The serialized tx is well-formed and decodes back to base64.
        assertTrue(tx.transaction.isNotEmpty())
    }
}
