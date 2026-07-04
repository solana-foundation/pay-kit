/**
 * Regression tests for the subscription co-sign / verify hardening
 * (C-1, A3, A5). Ports the Rust disallowed-program / non-index-0 tests to
 * TS and adds the channel-status and transaction-version parity guards.
 *
 *   (C-1a) validateActivationInstructions must REJECT any instruction whose
 *          program is outside the activation allowlist — never silently skip
 *          it — so an attacker cannot append a fund-draining System/SPL
 *          transfer that the sponsored fee payer would blindly co-sign.
 *   (C-1b) coSignBase64Transaction must refuse to sign when the server key
 *          is not the fee payer at account index 0.
 *   (A3)   verifyChannelAccountState must reject a channel whose on-chain
 *          status is not `open`.
 *   (A5)   every getCompiledTransactionMessageDecoder().decode site must
 *          reject non-legacy/v0 (e.g. v1) messages with a clean typed error
 *          rather than skipping the ALT guard or crashing with a TypeError.
 */
import {
    AccountRole,
    address,
    appendTransactionMessageInstructions,
    type Blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64Decoder,
    getBase64EncodedWireTransaction,
    getCompiledTransactionMessageEncoder,
    getTransactionEncoder,
    type Instruction,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    type TransactionPartialSigner,
} from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';
import { describe, expect, test } from 'vitest';

import {
    ASSOCIATED_TOKEN_PROGRAM,
    COMPUTE_BUDGET_PROGRAM,
    MEMO_PROGRAM,
    SUBSCRIPTIONS_CANCEL_DISCRIMINATOR,
    SUBSCRIPTIONS_PROGRAM,
    SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR,
    SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR,
    SYSTEM_PROGRAM,
    USDC,
} from '../constants.js';
import { getChannelEncoder } from '../generated/payment-channels/accounts/channel.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../generated/payment-channels/programs/paymentChannels.js';
import { ChannelStatus } from '../generated/payment-channels/types/channelStatus.js';
import { __testing } from '../server/Subscription.js';
import { verifyChannelAccountState } from '../server/session/on-chain.js';
import { coSignBase64Transaction } from '../utils/transactions.js';
import { verifyChargeTransaction } from '../server/Charge.js';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const OPERATOR = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const CHANNEL_ID = '11111111111111111111111111111111';
const DEVNET_USDC = USDC.devnet!;
const PROGRAM = PAYMENT_CHANNELS_PROGRAM_ADDRESS as string;

const activationChallenge = {
    methodDetails: { programId: SUBSCRIPTIONS_PROGRAM },
} as never;

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

/**
 * Build a fee-sponsored activation transaction (fee payer at index 0) with a
 * valid subscribe + transfer_subscription pair, plus any caller-supplied extra
 * instructions appended after the pair.
 */
async function buildSponsoredActivation(
    extra: (ctx: {
        feePayer: TransactionPartialSigner;
        subscriber: TransactionPartialSigner;
    }) => Instruction[] = () => [],
): Promise<{ transaction: string }> {
    const feePayer = await generateKeyPairSigner();
    const subscriber = await generateKeyPairSigner();
    const instructions = [
        subscribeIx(subscriber.address),
        transferIx(subscriber.address),
        ...extra({ feePayer, subscriber }),
    ];
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(feePayer, msg),
        msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
        msg => appendTransactionMessageInstructions(instructions, msg),
    );
    const signed = await partiallySignTransactionMessageWithSigners(txMessage);
    return { transaction: getBase64EncodedWireTransaction(signed) };
}

/** Encode a Channel account to base64 with a given status + field overrides. */
function encodeChannel(fields: {
    authorizedSigner: string;
    deposit: bigint;
    mint: string;
    payee: string;
    payer: string;
    status: number;
}): string {
    const bytes = getChannelEncoder().encode({
        discriminator: 0,
        version: 1,
        bump: 255,
        status: fields.status,
        salt: 7n,
        deposit: fields.deposit,
        settlement: { settled: 0n, payoutWatermark: 0n },
        closureStartedAt: 0n,
        payerWithdrawnAt: 0n,
        gracePeriod: 900,
        distributionHash: new Array(32).fill(0),
        payer: address(fields.payer),
        payee: address(fields.payee),
        authorizedSigner: address(fields.authorizedSigner),
        mint: address(fields.mint),
        rentPayer: address(OPERATOR),
    });
    return getBase64Decoder().decode(bytes);
}

function rpcWithChannel(data: string) {
    return {
        getAccountInfo: () => ({
            send: async () => ({ value: { data: [data, 'base64'], owner: PROGRAM } }),
        }),
    } as never;
}

/**
 * Hand-encode a v1 (versioned-with-config) wire transaction. A v1 message
 * decodes to a shape that carries neither `.instructions` nor
 * `.addressTableLookups`, so the pre-fix verifiers skip the ALT guard and then
 * crash on the instruction loop. Returns the base64 wire transaction.
 */
function buildV1WireTransaction(): string {
    const messageBytes = getCompiledTransactionMessageEncoder().encode({
        version: 1,
        header: { numSignerAccounts: 1, numReadonlySignerAccounts: 0, numReadonlyNonSignerAccounts: 1 },
        configMask: 0,
        lifetimeToken: BLOCKHASH,
        numInstructions: 1,
        numStaticAccounts: 2,
        staticAccounts: [address('4nd1msHzwUeoBpwSj9SVCkFyz9WD3Vv9pKrdmXaMEWfy'), address(SYSTEM_PROGRAM)],
        configValues: [],
        instructionHeaders: [{ programAccountIndex: 1, numInstructionAccounts: 1, numInstructionDataBytes: 3 }],
        instructionPayloads: [{ instructionAccountIndices: [0], instructionData: new Uint8Array([9, 9, 9]) }],
    } as never);
    const tx = {
        messageBytes,
        signatures: { '4nd1msHzwUeoBpwSj9SVCkFyz9WD3Vv9pKrdmXaMEWfy': new Uint8Array(64) },
    };
    return getBase64Decoder().decode(getTransactionEncoder().encode(tx as never));
}

// ══════════════════════════════════════════════════════════════════════
// C-1a: strict activation allowlist (reject, never skip)
// ══════════════════════════════════════════════════════════════════════

describe('validateActivationInstructions strict allowlist (C-1a)', () => {
    test('rejects an appended System transfer sourced from the fee payer', async () => {
        const { transaction } = await buildSponsoredActivation(({ feePayer, subscriber }) => [
            getTransferSolInstruction({ amount: 1_000_000_000n, destination: subscriber.address, source: feePayer }),
        ]);
        await expect(__testing.validateActivationInstructions(transaction, activationChallenge)).rejects.toThrow(
            /disallowed program/,
        );
    });

    test('rejects an appended instruction on an arbitrary unknown program', async () => {
        const stranger = await generateKeyPairSigner();
        const { transaction } = await buildSponsoredActivation(() => [
            {
                accounts: [],
                data: new Uint8Array([1, 2, 3]),
                programAddress: stranger.address,
            },
        ]);
        await expect(__testing.validateActivationInstructions(transaction, activationChallenge)).rejects.toThrow(
            /disallowed program/,
        );
    });

    test('rejects a disallowed subscriptions-program discriminator (cancel)', async () => {
        const { transaction } = await buildSponsoredActivation(({ subscriber }) => [
            {
                accounts: [{ address: subscriber.address, role: AccountRole.READONLY }],
                data: new Uint8Array([SUBSCRIPTIONS_CANCEL_DISCRIMINATOR]),
                programAddress: address(SUBSCRIPTIONS_PROGRAM),
            },
        ]);
        await expect(__testing.validateActivationInstructions(transaction, activationChallenge)).rejects.toThrow(
            /disallowed subscriptions-program instruction/,
        );
    });

    test('accepts the auxiliary allowlist programs (compute-budget, memo)', async () => {
        // Compute-budget (price/limit) and the optional external-id memo carry
        // no fee-payer fund/authority risk and are always allowed. A canonical
        // idempotent-ATA happy path is covered in subscription-activation-ata.
        const { transaction } = await buildSponsoredActivation(({ subscriber }) => [
            {
                accounts: [],
                data: new Uint8Array([2, 0x40, 0x0d, 0x03, 0x00]),
                programAddress: address(COMPUTE_BUDGET_PROGRAM),
            },
            {
                accounts: [{ address: subscriber.address, role: AccountRole.READONLY }],
                data: new TextEncoder().encode('ext-id'),
                programAddress: address(MEMO_PROGRAM),
            },
        ]);
        await expect(
            __testing.validateActivationInstructions(transaction, activationChallenge),
        ).resolves.toBeUndefined();
    });

    test('rejects a non-idempotent (Create, not CreateIdempotent) ATA instruction', async () => {
        const { transaction } = await buildSponsoredActivation(({ feePayer, subscriber }) => [
            {
                accounts: [
                    { address: feePayer.address, role: AccountRole.WRITABLE_SIGNER },
                    { address: subscriber.address, role: AccountRole.READONLY },
                ],
                // discriminator 0 == Create (not the allowed CreateIdempotent == 1)
                data: new Uint8Array([0]),
                programAddress: address(ASSOCIATED_TOKEN_PROGRAM),
            },
        ]);
        await expect(__testing.validateActivationInstructions(transaction, activationChallenge)).rejects.toThrow(
            /idempotent/i,
        );
    });

    test('still accepts a clean subscribe + transfer_subscription activation', async () => {
        const { transaction } = await buildSponsoredActivation();
        await expect(
            __testing.validateActivationInstructions(transaction, activationChallenge),
        ).resolves.toBeUndefined();
    });
});

// ══════════════════════════════════════════════════════════════════════
// C-1b: fee-payer index-0 pin on co-sign
// ══════════════════════════════════════════════════════════════════════

describe('coSignBase64Transaction fee-payer index-0 pin (C-1b)', () => {
    /**
     * Build a transaction where `serverKey` is a required signer but the fee
     * payer (account index 0) is someone else — i.e. the server key sits at a
     * non-zero signer index. The server must refuse to co-sign.
     */
    async function buildServerAtNonZeroIndex() {
        const attackerFeePayer = await generateKeyPairSigner();
        const serverKey = await generateKeyPairSigner();
        // A System transfer whose SOURCE (a required signer) is the server key,
        // draining the server, with the attacker at the fee-payer slot.
        const drain = getTransferSolInstruction({
            amount: 1_000_000_000n,
            destination: attackerFeePayer.address,
            source: serverKey,
        });
        const txMessage = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayer(attackerFeePayer.address, msg),
            msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
            msg => appendTransactionMessageInstructions([drain], msg),
        );
        const signed = await partiallySignTransactionMessageWithSigners(txMessage);
        return { serverKey, transaction: getBase64EncodedWireTransaction(signed) };
    }

    test('rejects when the server key is a signer at a non-zero index', async () => {
        const { serverKey, transaction } = await buildServerAtNonZeroIndex();
        let signCalled = false;
        const guardedSigner = {
            address: serverKey.address,
            async signTransactions(txs: unknown[]) {
                signCalled = true;
                return serverKey.signTransactions(txs as never);
            },
        } as unknown as TransactionPartialSigner;

        await expect(coSignBase64Transaction(guardedSigner, transaction)).rejects.toThrow(/index 0|fee payer/i);
        expect(signCalled).toBe(false);
    });

    test('still co-signs a transaction whose fee payer IS the server key at index 0', async () => {
        const feePayer = await generateKeyPairSigner();
        const sender = await generateKeyPairSigner();
        const recipient = await generateKeyPairSigner();
        const txMessage = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayer(feePayer.address, msg),
            msg => setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 1n }, msg),
            msg =>
                appendTransactionMessageInstructions(
                    [getTransferSolInstruction({ amount: 1_000n, destination: recipient.address, source: sender })],
                    msg,
                ),
        );
        const signed = await partiallySignTransactionMessageWithSigners(txMessage);
        const base64Tx = getBase64EncodedWireTransaction(signed);
        const result = await coSignBase64Transaction(feePayer, base64Tx);
        expect(typeof result === 'string' && result.length > 0).toBe(true);
        expect(result).not.toBe(base64Tx);
    });
});

// ══════════════════════════════════════════════════════════════════════
// A3: verifyChannelAccountState channel-status guard
// ══════════════════════════════════════════════════════════════════════

describe('verifyChannelAccountState channel-status guard (A3)', () => {
    const EXPECTED = {
        authorizedSigner: OPERATOR,
        deposit: 2_000n,
        mint: DEVNET_USDC,
        payee: RECIPIENT,
        payer: RECIPIENT,
    };

    test('rejects a channel whose on-chain status is not open (Closing)', async () => {
        const channel = encodeChannel({
            authorizedSigner: OPERATOR,
            deposit: 2_000n,
            mint: DEVNET_USDC,
            payee: RECIPIENT,
            payer: RECIPIENT,
            status: ChannelStatus.Closing,
        });
        await expect(
            verifyChannelAccountState({ channelId: CHANNEL_ID, expected: EXPECTED, rpc: rpcWithChannel(channel) }),
        ).rejects.toThrow(/status/i);
    });

    test('rejects a channel whose on-chain status is Finalized', async () => {
        const channel = encodeChannel({
            authorizedSigner: OPERATOR,
            deposit: 2_000n,
            mint: DEVNET_USDC,
            payee: RECIPIENT,
            payer: RECIPIENT,
            status: ChannelStatus.Finalized,
        });
        await expect(
            verifyChannelAccountState({ channelId: CHANNEL_ID, expected: EXPECTED, rpc: rpcWithChannel(channel) }),
        ).rejects.toThrow(/status/i);
    });

    test('accepts a channel whose on-chain status is open', async () => {
        const channel = encodeChannel({
            authorizedSigner: OPERATOR,
            deposit: 2_000n,
            mint: DEVNET_USDC,
            payee: RECIPIENT,
            payer: RECIPIENT,
            status: ChannelStatus.Open,
        });
        await expect(
            verifyChannelAccountState({ channelId: CHANNEL_ID, expected: EXPECTED, rpc: rpcWithChannel(channel) }),
        ).resolves.toBeUndefined();
    });
});

// ══════════════════════════════════════════════════════════════════════
// A5: transaction-version guard (reject v1, clean typed error not TypeError)
// ══════════════════════════════════════════════════════════════════════

describe('transaction-version guard (A5)', () => {
    test('validateActivationInstructions rejects a v1 message with a typed error', async () => {
        const wire = buildV1WireTransaction();
        let error: unknown;
        try {
            await __testing.validateActivationInstructions(wire, activationChallenge);
        } catch (e) {
            error = e;
        }
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).not.toMatch(/is not iterable|undefined \(reading|Cannot read/);
        expect((error as Error).message).toMatch(/version|legacy|not supported/i);
    });

    test('extractSubscriberFromTransaction rejects a v1 message with a typed error', () => {
        const wire = buildV1WireTransaction();
        let error: unknown;
        try {
            __testing.extractSubscriberFromTransaction(wire, activationChallenge);
        } catch (e) {
            error = e;
        }
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).not.toMatch(/is not iterable|undefined \(reading|Cannot read/);
    });

    test('verifyChargeTransaction rejects a v1 message with a typed error, not a TypeError', async () => {
        const wire = buildV1WireTransaction();
        const challenge = {
            amount: '1000',
            currency: 'sol',
            methodDetails: { network: 'mainnet' },
            recipient: RECIPIENT,
        } as never;
        let error: unknown;
        try {
            await verifyChargeTransaction(wire, challenge);
        } catch (e) {
            error = e;
        }
        expect(error).toBeInstanceOf(Error);
        expect(error).not.toBeInstanceOf(TypeError);
        expect((error as Error).message).not.toMatch(/is not iterable|undefined \(reading|Cannot read/);
        expect((error as Error).message).toMatch(/version|legacy|not supported/i);
    });
});
