// Server-side on-chain hardening tests:
//
//   - verifyOpenTx binds openPayload.signature to the transaction's own
//     first signature.
//   - verifyOpenTx accepts both legacy and v0 transaction encodings.
//   - submitOpenTx waits for on-chain confirmation before returning.
//   - submitInitMultiDelegateTxIfMissing is PDA-existence idempotent.
//   - session() with openTxSubmitter='server' does not rebroadcast the
//     open transaction on an idempotent open replay.

import {
    createKeyPairSignerFromPrivateKeyBytes,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getSignatureFromTransaction,
    getTransactionDecoder,
    getTransactionEncoder,
    type KeyPairSigner,
    type Signature,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { buildOpenPaymentChannelTransaction } from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { USDC } from '../constants.js';
import { session } from '../server/Session.js';
import {
    PAYMENT_CHANNELS_PROGRAM_ID,
    findMultiDelegatePda,
    submitInitMultiDelegateTxIfMissing,
    submitOpenTx,
    verifyOpenTx,
} from '../server/session/on-chain.js';
import { createMemorySessionStore } from '../server/session/store.js';

// ── fixtures ────────────────────────────────────────────────────────────

function makeSeed(byte: number): Uint8Array {
    const seed = new Uint8Array(32);
    seed.fill(byte);
    return seed;
}

async function loadFixedSigners() {
    return await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x11)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x12)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x13)),
    ]);
}

async function buildClientOpen(payer: KeyPairSigner, payee: KeyPairSigner, authorizedSigner: KeyPairSigner) {
    const request: SessionRequest = {
        cap: '1000000',
        currency: USDC.mainnet!,
        decimals: 6,
        network: 'localnet',
        operator: payer.address,
        recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
        recipient: payee.address,
    };
    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        deposit: 1_000_000n,
        gracePeriod: 900,
        programAddress: PAYMENT_CHANNELS_PROGRAM_ID,
        request,
        salt: 7n,
        signer: payer,
    });
    return { open, request };
}

function expectedFor(payer: KeyPairSigner, payee: KeyPairSigner, authorizedSigner: KeyPairSigner) {
    return {
        authorizedSigner: authorizedSigner.address,
        currency: USDC.mainnet!,
        maxCap: 5_000_000n,
        network: 'localnet',
        operator: payer.address,
        programId: PAYMENT_CHANNELS_PROGRAM_ID as string,
        recipient: payee.address,
    };
}

/** Extract the first (fee-payer) signature of a base64 wire transaction. */
function txSignature(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    return getSignatureFromTransaction(tx);
}

/** Re-encode a v0 wire transaction as a legacy wire transaction. */
function reencodeAsLegacy(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    const legacyMessageBytes = getCompiledTransactionMessageEncoder().encode({
        ...compiled,
        version: 'legacy',
    } as never);
    const legacyTx = getTransactionEncoder().encode({
        messageBytes: legacyMessageBytes as never,
        signatures: tx.signatures,
    });
    return getBase64Codec().decode(legacyTx);
}

const PLACEHOLDER_SIG = '1'.repeat(88);

// ── verifyOpenTx: signature binding ─────────────────────────────────────

describe('verifyOpenTx signature binding', () => {
    test('accepts when openPayload.signature equals the transaction signature', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);

        const result = await verifyOpenTx({
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: txSignature(open.transaction),
                transaction: open.transaction,
            },
        });
        expect(result.channelId).toBe(open.channelId);
    });

    test('rejects an openPayload.signature unrelated to the transaction', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // A different transaction's perfectly valid signature.
        const otherOpen = await buildOpenPaymentChannelTransaction({
            authorizedSigner: authorizedSigner.address,
            deposit: 500_000n,
            gracePeriod: 900,
            programAddress: PAYMENT_CHANNELS_PROGRAM_ID,
            request: {
                cap: '1000000',
                currency: USDC.mainnet!,
                decimals: 6,
                network: 'localnet',
                operator: payer.address,
                recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
                recipient: payee.address,
            },
            salt: 8n,
            signer: payer,
        });

        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: txSignature(otherOpen.transaction),
                    transaction: open.transaction,
                },
            }),
        ).rejects.toThrow(/transaction signature/);
    });

    test('placeholder signatures skip the binding check', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);

        const result = await verifyOpenTx({
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
        });
        expect(result.deposit).toBe(1_000_000n);
    });
});

// ── verifyOpenTx: legacy transaction encoding ───────────────────────────

describe('verifyOpenTx legacy encoding', () => {
    test('decodes a legacy-encoded open transaction (Rust client wire format)', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const legacyTransaction = reencodeAsLegacy(open.transaction);
        expect(legacyTransaction).not.toBe(open.transaction);

        const result = await verifyOpenTx({
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: legacyTransaction,
            },
        });
        expect(result.channelId).toBe(open.channelId);
        expect(result.deposit).toBe(1_000_000n);
        expect(result.salt).toBe(7n);
    });
});

// ── submitOpenTx: confirmation gating ───────────────────────────────────

interface MockStatus {
    confirmationStatus?: string;
    err: unknown;
}

function makeSubmitRpc(statusSequence: (MockStatus | null)[]) {
    const sends: string[] = [];
    let statusCalls = 0;
    return {
        getSignatureStatuses: (_sigs: readonly Signature[]) => ({
            send: async () => {
                const status =
                    statusCalls < statusSequence.length
                        ? statusSequence[statusCalls]
                        : statusSequence[statusSequence.length - 1];
                statusCalls += 1;
                return { value: [status ?? null] };
            },
        }),
        sendTransaction: (wire: string) => ({
            send: async () => {
                sends.push(wire);
                return 'OpenSig1111111111111111111111111111111111111111111111111111111' as Signature;
            },
        }),
        sends,
        statusCallCount: () => statusCalls,
    };
}

describe('submitOpenTx confirmation', () => {
    test('polls until the signature is confirmed before returning', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const rpc = makeSubmitRpc([
            null,
            { confirmationStatus: 'processed', err: null },
            { confirmationStatus: 'confirmed', err: null },
        ]);

        const result = await submitOpenTx({
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
            rpc,
        });
        expect(result.channelId).toBe(open.channelId);
        expect(rpc.sends).toHaveLength(1);
        expect(rpc.statusCallCount()).toBeGreaterThanOrEqual(3);
    });

    test('throws when confirmation never arrives within the timeout', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const rpc = makeSubmitRpc([null]);

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, timeoutMs: 20 },
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: open.transaction,
                },
                rpc,
            }),
        ).rejects.toThrow(/timed out/);
    });

    test('throws when the transaction failed on-chain', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const rpc = makeSubmitRpc([{ confirmationStatus: 'confirmed', err: { InstructionError: [0, 'Custom'] } }]);

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: open.transaction,
                },
                rpc,
            }),
        ).rejects.toThrow(/failed on-chain/);
    });

    test('aborts when the signal fires', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const rpc = makeSubmitRpc([null]);
        const controller = new AbortController();
        controller.abort();

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, signal: controller.signal, timeoutMs: 2_000 },
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: open.transaction,
                },
                rpc,
            }),
        ).rejects.toThrow(/aborted/);
    });
});

// ── session() openTxSubmitter='server': no rebroadcast on replay ────────

describe("session() openTxSubmitter='server' replay", () => {
    test('an idempotent open replay does not rebroadcast the transaction', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const store = createMemorySessionStore();
        const rpc = makeSubmitRpc([{ confirmationStatus: 'confirmed', err: null }]);

        const method = session({
            cap: 5_000_000n,
            currency: USDC.mainnet!,
            decimals: 6,
            network: 'localnet',
            openTxSubmitter: 'server',
            operator: payer.address,
            pricing: {},
            recipient: payee.address,
            rpc: rpc as never,
            store,
        });

        const credential = {
            challenge: {
                id: 'challenge-id-123',
                intent: 'session',
                method: 'solana',
                realm: 'api.test',
                request: {
                    cap: '5000000',
                    currency: USDC.mainnet!,
                    operator: payer.address,
                    recipient: payee.address,
                },
            },
            payload: {
                action: 'open',
                authorizedSigner: authorizedSigner.address,
                channelId: open.channelId,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
        } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];

        const first = await method.verify({ credential, request: {} as never });
        expect(first.status).toBe('success');
        expect(rpc.sends).toHaveLength(1);

        const replay = await method.verify({ credential, request: {} as never });
        expect(replay.status).toBe('success');
        expect(rpc.sends).toHaveLength(1);

        const state = await store.getChannel(open.channelId);
        expect(state?.deposit).toBe(1_000_000n);
        expect(state?.cumulative).toBe(0n);
    });
});

// ── submitInitMultiDelegateTxIfMissing ──────────────────────────────────

describe('submitInitMultiDelegateTxIfMissing', () => {
    function makeMultiDelegateRpc(pdaExists: boolean) {
        const sends: string[] = [];
        const accountLookups: string[] = [];
        return {
            accountLookups,
            getAccountInfo: (addr: string) => ({
                send: async () => {
                    accountLookups.push(addr);
                    return { value: pdaExists ? { lamports: 1n } : null };
                },
            }),
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ confirmationStatus: 'confirmed', err: null }] }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    return 'InitSig1111111111111111111111111111111111111111111111111111111' as Signature;
                },
            }),
            sends,
        };
    }

    test('submits the init transaction when the PDA is missing', async () => {
        const [owner] = await loadFixedSigners();
        const rpc = makeMultiDelegateRpc(false);
        const signature = await submitInitMultiDelegateTxIfMissing({
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            initMultiDelegateTx: 'BASE64-INIT-TX',
            mint: USDC.mainnet!,
            owner: owner.address,
            rpc: rpc as never,
        });
        expect(signature).toBeDefined();
        expect(rpc.sends).toEqual(['BASE64-INIT-TX']);

        const pda = await findMultiDelegatePda({ mint: USDC.mainnet!, user: owner.address });
        expect(rpc.accountLookups).toEqual([pda]);
    });

    test('skips submission when the PDA already exists', async () => {
        const [owner] = await loadFixedSigners();
        const rpc = makeMultiDelegateRpc(true);
        const signature = await submitInitMultiDelegateTxIfMissing({
            initMultiDelegateTx: 'BASE64-INIT-TX',
            mint: USDC.mainnet!,
            owner: owner.address,
            rpc: rpc as never,
        });
        expect(signature).toBeUndefined();
        expect(rpc.sends).toHaveLength(0);
    });

    test('pull operatedVoucher open submits the init tx idempotently through session()', async () => {
        const [owner, payee, authorizedSigner] = await loadFixedSigners();
        const merchant = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x14));
        const store = createMemorySessionStore();
        const rpc = makeMultiDelegateRpc(false);

        const method = session({
            cap: 5_000_000n,
            currency: USDC.mainnet!,
            decimals: 6,
            modes: ['pull'],
            network: 'localnet',
            operator: owner.address,
            pricing: {},
            pullVoucherStrategy: 'operatedVoucher',
            recipient: payee.address,
            rpc: rpc as never,
            signer: merchant,
            store,
        });

        const credential = {
            challenge: {
                id: 'challenge-id-456',
                intent: 'session',
                method: 'solana',
                realm: 'api.test',
                request: {
                    cap: '5000000',
                    currency: USDC.mainnet!,
                    operator: owner.address,
                    recipient: payee.address,
                },
            },
            payload: {
                action: 'open',
                approvedAmount: '1000',
                authorizedSigner: authorizedSigner.address,
                initMultiDelegateTx: 'BASE64-INIT-TX',
                mint: USDC.mainnet!,
                mode: 'pull',
                owner: owner.address,
                signature: 'sig-1',
                tokenAccount: 'So11111111111111111111111111111111111111112',
            },
        } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];

        const receipt = await method.verify({ credential, request: {} as never });
        expect(receipt.status).toBe('success');
        expect(rpc.sends).toEqual(['BASE64-INIT-TX']);
        expect(await store.getChannel('So11111111111111111111111111111111111111112')).toBeDefined();
    });
});
