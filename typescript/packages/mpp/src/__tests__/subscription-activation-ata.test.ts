// Regression tests for the subscription-activation ATA scope check (M-5).
//
// An ATA `CreateIdempotent` instruction names its funding account (charged the
// account's rent) as a required signer. Before this fix the subscription
// activation allowlist accepted ANY Associated-Token-Account instruction
// (originally a bare skip, later a discriminator-only check), so a client could
// make the sponsored fee payer fund an arbitrary ATA. `validateActivationInstructions`
// now validates the instruction the same way the charge verifier does:
// idempotent discriminator, canonical 6-account layout, funding == fee payer,
// mint == plan mint, owner authorized (subscriber/recipient/puller), token
// program == the configured one, and the ATA address re-derives.
//
// These tests drive the pure `__testing.validateActivationInstructions`
// (which runs before co-sign in the real settle path) and, as a belt-and-braces
// end-to-end check, drive `verify()` with a fee-payer signer that throws if it
// is ever invoked — proving validation rejects the malicious ATA before any
// server signature is produced.

import {
    AccountRole,
    address,
    appendTransactionMessageInstructions,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64EncodedWireTransaction,
    type Instruction,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    type TransactionPartialSigner,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';
import { describe, expect, test } from 'vitest';

import {
    ASSOCIATED_TOKEN_PROGRAM,
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
} from '../constants.js';
import { __testing, subscription } from '../server/Subscription.js';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
const PLAN_ID = '8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const PULLER = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';

/** subscriptions-program subscribe instruction, subscriber-owned. */
function subscribeIx(subscriber: string): Instruction {
    return {
        accounts: [{ address: address(subscriber), role: AccountRole.WRITABLE_SIGNER }],
        data: new Uint8Array([SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
}

/** subscriptions-program transfer_subscription instruction, subscriber-owned. */
function transferIx(subscriber: string): Instruction {
    return {
        accounts: [{ address: address(subscriber), role: AccountRole.READONLY }],
        data: new Uint8Array([SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR]),
        programAddress: address(SUBSCRIPTIONS_PROGRAM),
    };
}

/** Fields of the ATA `CreateIdempotent` instruction the negative cases corrupt. */
type AtaFields = {
    accounts?: { address: string; role: AccountRole }[];
    data?: Uint8Array;
    payer: string;
    ata: string;
    owner: string;
    mint: string;
    systemProgram: string;
    tokenProgram: string;
};

/** Build an ATA `CreateIdempotent` instruction with a fully controllable layout. */
function ataIx(fields: AtaFields): Instruction {
    const accounts = fields.accounts ?? [
        { address: fields.payer, role: AccountRole.WRITABLE_SIGNER },
        { address: fields.ata, role: AccountRole.WRITABLE },
        { address: fields.owner, role: AccountRole.READONLY },
        { address: fields.mint, role: AccountRole.READONLY },
        { address: fields.systemProgram, role: AccountRole.READONLY },
        { address: fields.tokenProgram, role: AccountRole.READONLY },
    ];
    return {
        accounts: accounts.map(a => ({ address: address(a.address), role: a.role })),
        data: fields.data ?? new Uint8Array([1]),
        programAddress: address(ASSOCIATED_TOKEN_PROGRAM),
    };
}

/**
 * Build a fee-sponsored activation transaction (fee payer at index 0, a
 * distinct subscriber signer) with a subscribe + transfer pair and a
 * caller-supplied ATA instruction. Only the subscriber signs, leaving the
 * fee-payer slot for the server to co-sign — the exact shape the server
 * validates before co-signing. Returns the wire transaction plus the two
 * addresses so tests can construct canonical or malicious ATA fields.
 */
async function buildActivation(
    buildAta: (ctx: { feePayer: TransactionPartialSigner; subscriber: TransactionPartialSigner }) => Instruction,
    feePayerSigner?: TransactionPartialSigner,
): Promise<{ transaction: string; feePayer: string; subscriber: string }> {
    const feePayer = feePayerSigner ?? (await generateKeyPairSigner());
    const subscriber = await generateKeyPairSigner();
    const instructions = [
        subscribeIx(subscriber.address),
        transferIx(subscriber.address),
        buildAta({ feePayer, subscriber }),
    ];
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(feePayer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    const signed = await partiallySignTransactionMessageWithSigners(txMessage, {
        signers: [subscriber],
    } as never);
    return {
        transaction: getBase64EncodedWireTransaction(signed),
        feePayer: feePayer.address,
        subscriber: subscriber.address,
    };
}

/** A fee-sponsored activation challenge that pins the plan mint / owners. */
function challengeFor(feePayer: string) {
    return {
        methodDetails: {
            feePayer: true,
            feePayerKey: feePayer,
            mint: MINT,
            planId: PLAN_ID,
            programId: SUBSCRIPTIONS_PROGRAM,
            puller: PULLER,
            tokenProgram: TOKEN_PROGRAM,
        },
        recipient: RECIPIENT,
    } as never;
}

async function canonicalAta(owner: string, mint = MINT, tokenProgram = TOKEN_PROGRAM): Promise<string> {
    const [ata] = await findAssociatedTokenPda({
        mint: address(mint),
        owner: address(owner),
        tokenProgram: address(tokenProgram),
    });
    return ata;
}

describe('subscription activation ATA scope (M-5)', () => {
    test('canonical CreateIdempotent for the plan mint owned by the subscriber is accepted', async () => {
        const feePayer = await generateKeyPairSigner();
        const subscriber = await generateKeyPairSigner();
        const ata = await canonicalAta(subscriber.address);
        const instructions = [
            subscribeIx(subscriber.address),
            transferIx(subscriber.address),
            ataIx({
                payer: feePayer.address,
                ata,
                owner: subscriber.address,
                mint: MINT,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
            }),
        ];
        const txMessage = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayerSigner(feePayer, msg),
            msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
            msg => appendTransactionMessageInstructions(instructions, msg),
        );
        const signed = await partiallySignTransactionMessageWithSigners(txMessage, {
            signers: [subscriber],
        } as never);
        const transaction = getBase64EncodedWireTransaction(signed);
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer.address)),
        ).resolves.toBeUndefined();
    });

    test('(a) rejects an ATA funded by an account other than the fee payer', async () => {
        const stranger = await generateKeyPairSigner();
        const { transaction, feePayer } = await buildActivation(({ subscriber: sub }) =>
            ataIx({
                payer: stranger.address, // not the fee payer at index 0
                ata: stranger.address, // (address is irrelevant; the payer check fires first)
                owner: sub.address,
                mint: MINT,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
            }),
        );
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer)),
        ).rejects.toThrow(/ATA payer must be the transaction fee payer/);
    });

    test('(b) rejects an ATA created for a mint other than the plan mint', async () => {
        const wrongMint = '4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R';
        const { transaction, feePayer } = await buildActivation(({ feePayer: fp, subscriber: sub }) =>
            ataIx({
                payer: fp.address,
                ata: sub.address, // does not re-derive, but the mint check fires first
                owner: sub.address,
                mint: wrongMint,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
            }),
        );
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer)),
        ).rejects.toThrow(/ATA creation mint does not match the plan mint/);
    });

    test('(c) rejects an ATA whose owner is not authorized by the challenge', async () => {
        const stranger = await generateKeyPairSigner();
        const { transaction, feePayer } = await buildActivation(({ feePayer: fp }) =>
            ataIx({
                payer: fp.address,
                ata: stranger.address,
                owner: stranger.address, // neither subscriber, recipient, nor puller
                mint: MINT,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
            }),
        );
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer)),
        ).rejects.toThrow(/ATA creation owner is not authorized by the challenge/);
    });

    test('(d) rejects a non-canonical layout (wrong discriminator)', async () => {
        const { transaction, feePayer } = await buildActivation(({ feePayer: fp, subscriber: sub }) =>
            ataIx({
                payer: fp.address,
                ata: sub.address,
                owner: sub.address,
                mint: MINT,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
                data: new Uint8Array([0]), // Create (0), not CreateIdempotent (1)
            }),
        );
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer)),
        ).rejects.toThrow(/idempotent/i);
    });

    test('(d) rejects a non-canonical layout (wrong account count)', async () => {
        const { transaction, feePayer } = await buildActivation(({ feePayer: fp, subscriber: sub }) =>
            ataIx({
                payer: fp.address,
                ata: sub.address,
                owner: sub.address,
                mint: MINT,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
                // Drop the token-program account so the layout is 5, not 6.
                accounts: [
                    { address: fp.address, role: AccountRole.WRITABLE_SIGNER },
                    { address: sub.address, role: AccountRole.WRITABLE },
                    { address: sub.address, role: AccountRole.READONLY },
                    { address: MINT, role: AccountRole.READONLY },
                    { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
                ],
            }),
        );
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer)),
        ).rejects.toThrow(/Unexpected ATA creation account layout/);
    });

    test('(d) rejects a token program that does not match the configured one', async () => {
        // Use the other supported token program so it passes the "supported"
        // gate but fails the configured-program equality gate. Re-derive the ATA
        // against the substituted program so the only failing check is the
        // token-program mismatch.
        const feePayer = await generateKeyPairSigner();
        const subscriber = await generateKeyPairSigner();
        const ata = await canonicalAta(subscriber.address, MINT, TOKEN_2022_PROGRAM);
        const instructions = [
            subscribeIx(subscriber.address),
            transferIx(subscriber.address),
            ataIx({
                payer: feePayer.address,
                ata,
                owner: subscriber.address,
                mint: MINT,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_2022_PROGRAM,
            }),
        ];
        const txMessage = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayerSigner(feePayer, msg),
            msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
            msg => appendTransactionMessageInstructions(instructions, msg),
        );
        const signed = await partiallySignTransactionMessageWithSigners(txMessage, {
            signers: [subscriber],
        } as never);
        const transaction = getBase64EncodedWireTransaction(signed);
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer.address)),
        ).rejects.toThrow(/ATA creation token program does not match the configured token program/);
    });

    test('(e) rejects an ATA address that does not re-derive from (owner, mint, token)', async () => {
        const bogus = await generateKeyPairSigner();
        const { transaction, feePayer } = await buildActivation(({ feePayer: fp, subscriber: sub }) =>
            ataIx({
                payer: fp.address,
                ata: bogus.address, // not the canonical ATA for (subscriber, mint, token)
                owner: sub.address,
                mint: MINT,
                systemProgram: SYSTEM_PROGRAM,
                tokenProgram: TOKEN_PROGRAM,
            }),
        );
        await expect(
            __testing.validateActivationInstructions(transaction, challengeFor(feePayer)),
        ).rejects.toThrow(/ATA creation address does not match owner\/mint\/token program/);
    });

    test('verify() rejects a malicious ATA before the fee-payer signer is invoked', async () => {
        // Build the activation with a real fee-payer keypair (index 0), then
        // hand the server a signer wrapping that same address whose
        // signTransactions throws if it is ever reached. A correct verifier
        // rejects the malicious ATA during scope validation, so the signer is
        // never touched.
        const feePayerSigner = await generateKeyPairSigner();
        let signerInvoked = false;
        const guardedSigner: TransactionPartialSigner = {
            address: feePayerSigner.address,
            signTransactions: () => {
                signerInvoked = true;
                throw new Error('fee-payer signer must not be invoked for a rejected activation');
            },
        };

        const stranger = await generateKeyPairSigner();
        const { transaction } = await buildActivation(
            ({ feePayer: fp }) =>
                ataIx({
                    payer: fp.address,
                    ata: stranger.address,
                    owner: stranger.address, // unauthorized owner — the griefing shape
                    mint: MINT,
                    systemProgram: SYSTEM_PROGRAM,
                    tokenProgram: TOKEN_PROGRAM,
                }),
            feePayerSigner,
        );

        const method = subscription({
            decimals: 6,
            mint: MINT,
            network: 'devnet',
            periodCount: 30,
            periodUnit: 'day',
            planId: PLAN_ID,
            puller: PULLER,
            recipient: RECIPIENT,
            rpcUrl: 'https://mock-rpc',
            signer: guardedSigner,
            tokenProgram: TOKEN_PROGRAM,
        });

        const credential = {
            challenge: {
                id: 'test-challenge',
                request: {
                    amount: '10000000',
                    currency: MINT,
                    methodDetails: {
                        decimals: 6,
                        feePayer: true,
                        feePayerKey: feePayerSigner.address,
                        mint: MINT,
                        network: 'devnet',
                        planId: PLAN_ID,
                        programId: SUBSCRIPTIONS_PROGRAM,
                        puller: PULLER,
                        tokenProgram: TOKEN_PROGRAM,
                    },
                    periodCount: '30',
                    periodUnit: 'day',
                    recipient: RECIPIENT,
                },
            },
            payload: { transaction, type: 'transaction' },
        };

        await expect(
            method.verify!({ credential: credential as never, request: {} as never }),
        ).rejects.toThrow(/ATA creation owner is not authorized by the challenge/);
        expect(signerInvoked).toBe(false);
    });
});
