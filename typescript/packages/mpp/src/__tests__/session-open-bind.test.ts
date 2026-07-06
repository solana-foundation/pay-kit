// Regression tests for the bare push-open binding fix.
//
// A push-mode open payload without transaction bytes asserts
// `{channelId, deposit, signature}`. Before the fix, a configured RPC
// only confirmed the signature succeeded — any unrelated landed
// transaction let a client register a fake channel with an arbitrary
// deposit. The server must fetch the transaction behind the signature
// and run the full verifyOpenTx binding against it; without an RPC the
// bare assertion is only accepted under the explicit `trustedClientOpen`
// opt-in.

import {
    createKeyPairSignerFromPrivateKeyBytes,
    generateKeyPairSigner,
    getBase64Codec,
    getSignatureFromTransaction,
    getTransactionDecoder,
    type KeyPairSigner,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { buildOpenPaymentChannelTransaction } from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { USDC } from '../constants.js';
import { session } from '../server/Session.js';
import { createMemorySessionStore } from '../server/session/store.js';

const PROGRAM_ID = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

function makeSeed(byte: number): Uint8Array {
    const seed = new Uint8Array(32);
    seed.fill(byte);
    return seed;
}

async function loadSigners() {
    return await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x11)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x12)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x13)),
    ]);
}

/** Build a real, signed payment-channel open transaction. */
async function buildOpen(payer: KeyPairSigner, payee: KeyPairSigner, authorizedSigner: KeyPairSigner) {
    const request: SessionRequest = {
        cap: '5000000',
        currency: USDC.mainnet!,
        decimals: 6,
        modes: ['push'],
        network: 'localnet',
        operator: payer.address,
        recentBlockhash: BLOCKHASH as never,
        recipient: payee.address,
    };
    return await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        deposit: 1_000_000n,
        gracePeriod: 900,
        programAddress: PROGRAM_ID,
        request,
        salt: 11n,
        signer: payer,
    });
}

/** Extract the first (fee-payer) signature of a base64-encoded transaction. */
function extractTxSignature(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    return getSignatureFromTransaction(tx) as string;
}

/** RPC mock serving canned base64 transactions keyed by signature. */
function mockTxRpc(transactions: Record<string, string>) {
    return {
        getSignatureStatuses: (sigs: readonly string[]) => ({
            send: async () => ({ value: sigs.map(sig => (transactions[sig] !== undefined ? { err: null } : null)) }),
        }),
        getTransaction: (sig: string) => ({
            send: async () => {
                const tx = transactions[sig];
                if (tx === undefined) return null;
                return { meta: { err: null }, transaction: [tx, 'base64'] };
            },
        }),
    };
}

function sessionParams(payer: KeyPairSigner, payee: KeyPairSigner, overrides: Record<string, unknown> = {}) {
    return {
        cap: 5_000_000n,
        currency: USDC.mainnet!,
        decimals: 6,
        network: 'localnet',
        operator: payer.address,
        pricing: {},
        programId: PROGRAM_ID,
        recipient: payee.address,
        ...overrides,
    } as Parameters<typeof session>[0];
}

function openCred(payload: Record<string, unknown>) {
    return {
        challenge: {
            id: 'challenge-id-123',
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: { cap: '5000000', currency: USDC.mainnet! },
        },
        payload: { action: 'open', mode: 'push', ...payload },
    } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];
}

describe('session() verify() bare push open binding', () => {
    test('binds the asserted open to the fetched transaction and records the payer', async () => {
        const [payer, payee, authorized] = await loadSigners();
        const open = await buildOpen(payer, payee, authorized);
        const signature = extractTxSignature(open.transaction);
        const store = createMemorySessionStore();
        const method = session(
            sessionParams(payer, payee, { rpc: mockTxRpc({ [signature]: open.transaction }) as never, store }),
        );

        const receipt = await method.verify({
            credential: openCred({
                authorizedSigner: authorized.address,
                channelId: open.channelId,
                deposit: open.deposit,
                signature,
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        const state = await store.getChannel(open.channelId);
        expect(state?.deposit).toBe(1_000_000n);
        // The channel payer must come from the verified transaction, not
        // from any client-asserted payload field.
        expect(state?.operator).toBe(payer.address);
    });

    test('rejects a fake channel asserted against an unrelated successful signature', async () => {
        const [payer, payee, authorized] = await loadSigners();
        // The unrelated-but-landed transaction is a real open... for a
        // DIFFERENT payee/channel. Its signature is alive and successful.
        const stranger = await generateKeyPairSigner();
        const unrelated = await buildOpen(payer, stranger, authorized);
        const signature = extractTxSignature(unrelated.transaction);
        const store = createMemorySessionStore();
        const method = session(
            sessionParams(payer, payee, { rpc: mockTxRpc({ [signature]: unrelated.transaction }) as never, store }),
        );

        await expect(
            method.verify({
                credential: openCred({
                    authorizedSigner: authorized.address,
                    channelId: '11111111111111111111111111111111',
                    deposit: '4999999',
                    signature,
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/payee/);
        expect(await store.getChannel('11111111111111111111111111111111')).toBeUndefined();
    });

    test('rejects an asserted deposit that does not match the transaction', async () => {
        const [payer, payee, authorized] = await loadSigners();
        const open = await buildOpen(payer, payee, authorized);
        const signature = extractTxSignature(open.transaction);
        const method = session(
            sessionParams(payer, payee, { rpc: mockTxRpc({ [signature]: open.transaction }) as never }),
        );

        await expect(
            method.verify({
                credential: openCred({
                    authorizedSigner: authorized.address,
                    channelId: open.channelId,
                    deposit: '2000000',
                    signature,
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/asserted deposit 2000000 != transaction deposit 1000000/);
    });

    test('rejects an asserted channelId that does not match the transaction', async () => {
        const [payer, payee, authorized] = await loadSigners();
        const open = await buildOpen(payer, payee, authorized);
        const signature = extractTxSignature(open.transaction);
        const method = session(
            sessionParams(payer, payee, { rpc: mockTxRpc({ [signature]: open.transaction }) as never }),
        );

        await expect(
            method.verify({
                credential: openCred({
                    authorizedSigner: authorized.address,
                    channelId: '11111111111111111111111111111111',
                    deposit: open.deposit,
                    signature,
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/channelId .* != tx channel/);
    });

    test('fails closed when the configured rpc cannot fetch transactions', async () => {
        const [payer, payee, authorized] = await loadSigners();
        const open = await buildOpen(payer, payee, authorized);
        const signature = extractTxSignature(open.transaction);
        const statusOnlyRpc = {
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({ value: sigs.map(() => ({ err: null })) }),
            }),
        };
        const method = session(sessionParams(payer, payee, { rpc: statusOnlyRpc as never }));

        await expect(
            method.verify({
                credential: openCred({
                    authorizedSigner: authorized.address,
                    channelId: open.channelId,
                    deposit: open.deposit,
                    signature,
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/does not expose getTransaction/);
    });

    test('rejects a bare push open with no rpc unless trustedClientOpen is set', async () => {
        const [payer, payee, authorized] = await loadSigners();
        const method = session(sessionParams(payer, payee));

        await expect(
            method.verify({
                credential: openCred({
                    authorizedSigner: authorized.address,
                    channelId: '11111111111111111111111111111111',
                    deposit: '1000',
                    signature: 'open-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/requires an rpc for verification/);
    });

    test('accepts a bare push open with no rpc under the trustedClientOpen opt-in', async () => {
        const [payer, payee, authorized] = await loadSigners();
        const store = createMemorySessionStore();
        const method = session(sessionParams(payer, payee, { store, trustedClientOpen: true }));

        const receipt = await method.verify({
            credential: openCred({
                authorizedSigner: authorized.address,
                channelId: '11111111111111111111111111111111',
                deposit: '1000',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect((await store.getChannel('11111111111111111111111111111111'))?.deposit).toBe(1_000n);
    });

    test('push open WITH transaction bytes still verifies without trustedClientOpen', async () => {
        const [payer, payee, authorized] = await loadSigners();
        const open = await buildOpen(payer, payee, authorized);
        const store = createMemorySessionStore();
        const method = session(sessionParams(payer, payee, { store }));

        const receipt = await method.verify({
            credential: openCred({
                authorizedSigner: authorized.address,
                channelId: open.channelId,
                deposit: open.deposit,
                gracePeriod: open.gracePeriod,
                mint: open.mint,
                payee: open.payee,
                payer: open.payer,
                salt: open.salt,
                signature: '1'.repeat(88),
                transaction: open.transaction,
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect((await store.getChannel(open.channelId))?.deposit).toBe(1_000_000n);
    });
});
