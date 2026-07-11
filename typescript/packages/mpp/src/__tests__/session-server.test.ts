// Unit tests for the server-side Session method.
//
// The dispatcher (open/voucher/commit/topUp/close) is exercised against
// a mocked SessionStore + an in-memory KeyPairSigner used to sign
// vouchers. The 402 challenge body is also snapshotted against the
// canonical Methods.ts schema so future schema drifts are caught here.

import {
    generateKeyPairSigner,
    getBase58Decoder,
    getBase64Codec,
    getSignatureFromTransaction,
    getTransactionDecoder,
    type KeyPairSigner,
} from '@solana/kit';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import * as Methods from '../Methods.js';
import { session } from '../server/Session.js';
import { type ChannelState, createMemorySessionStore, type SessionStore } from '../server/session/store.js';
import type { SignedVoucher, VoucherData } from '../shared/session-types.js';
import { encodeVoucherMessage } from '../shared/voucher.js';

// ── Fixtures ──────────────────────────────────────────────────────────────

const OPERATOR = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const RECIPIENT = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';

function signedWireSignature(wire: string): string {
    return getSignatureFromTransaction(getTransactionDecoder().decode(getBase64Codec().encode(wire)));
}

/**
 * Minimal RPC mock exposing `getSignatureStatuses` driven by a lookup
 * table. Unknown signatures resolve to `null` (not found).
 */
function mockStatusRpc(statuses: Record<string, { err: unknown } | null | undefined>) {
    const calls: string[] = [];
    return {
        calls,
        getSignatureStatuses: (sigs: readonly string[]) => ({
            send: async () => {
                calls.push(...sigs);
                return {
                    context: { slot: 42 },
                    value: sigs.map(sig => {
                        const status = statuses[sig];
                        return status ? { ...status, confirmationStatus: 'confirmed' } : null;
                    }),
                };
            },
        }),
    };
}

const FAR_FUTURE = Math.floor(Date.now() / 1000) + 3600;

async function makeSignedVoucher(
    signer: KeyPairSigner,
    channelId: string,
    cumulative: bigint,
    expiresAt: number = FAR_FUTURE,
): Promise<SignedVoucher> {
    const data: VoucherData = {
        channelId,
        cumulativeAmount: cumulative.toString(),
        expiresAt,
    };
    const message = encodeVoucherMessage(data);
    const [signatures] = await signer.signMessages([{ content: message, signatures: {} }]);
    const sigBytes = signatures?.[signer.address];
    if (!sigBytes) throw new Error('signer produced no signature');
    return { data, signature: getBase58Decoder().decode(new Uint8Array(sigBytes)) };
}

function makeCred<P>(payload: P, requestOverrides: Record<string, unknown> = {}) {
    return {
        challenge: {
            id: 'challenge-id-123',
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: {
                cap: '1000000',
                currency: 'USDC',
                operator: OPERATOR,
                recipient: RECIPIENT,
                ...requestOverrides,
            },
        },
        payload,
    } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];
}

// ── 402 challenge body snapshot ─────────────────────────────────────────

describe('session() request()', () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
        originalFetch = globalThis.fetch;
        // The blockhash prefetch response also carries the current slot in
        // its context — the server lifts it into the challenge `recentSlot`.
        globalThis.fetch = vi.fn(
            async () =>
                new Response(
                    JSON.stringify({
                        id: 1,
                        jsonrpc: '2.0',
                        result: {
                            context: { slot: 123456 },
                            value: {
                                blockhash: 'MockBlockhash1111111111111111111111111111111',
                                lastValidBlockHeight: 1,
                            },
                        },
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } },
                ),
        ) as typeof globalThis.fetch;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    test('builds a SessionRequest that satisfies the canonical schema', async () => {
        const method = session({
            allowUnsafeEphemeralStoreOffLocalnet: true,
            cap: 10_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'devnet',
            operator: OPERATOR,
            pricing: { perDelivery: 100n },
            recipient: RECIPIENT,
        });

        const result = await method.request!({
            credential: null,
            request: { cap: '1000000', currency: 'USDC', operator: '', recipient: '' },
        });

        const parsed = Methods.session.schema.request.parse(result);
        expect(parsed.cap).toBe('1000000');
        expect(parsed.currency).toBe('USDC');
        expect(parsed.operator).toBe(OPERATOR);
        expect(parsed.recipient).toBe(RECIPIENT);
        expect(parsed.network).toBe('devnet');
        expect(parsed.decimals).toBe(6);
        expect(parsed.recentBlockhash).toBe('MockBlockhash1111111111111111111111111111111');
        expect(parsed.recentSlot).toBe('123456');
        expect(parsed.modes).toBeUndefined();
    });

    test('clamps requested cap to the server max', async () => {
        const method = session({
            allowUnsafeEphemeralStoreOffLocalnet: true,
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'devnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        });
        const result = await method.request!({
            credential: null,
            request: { cap: '50000000', currency: 'USDC', operator: '', recipient: '' },
        });
        expect(result.cap).toBe('1000000');
    });

    test('includes modes + pullVoucherStrategy when pull is advertised', async () => {
        const method = session({
            allowUnsafeEphemeralStoreOffLocalnet: true,
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            modes: ['pull', 'push'],
            network: 'devnet',
            operator: OPERATOR,
            pricing: {},
            pullVoucherStrategy: 'clientVoucher',
            recipient: RECIPIENT,
        });

        const result = await method.request!({
            credential: null,
            request: { cap: '1000000', currency: 'USDC', operator: '', recipient: '' },
        });
        expect(result.modes).toEqual(['pull', 'push']);
        expect(result.pullVoucherStrategy).toBe('clientVoucher');
    });

    test('skips blockhash/slot prefetch when a credential is present', async () => {
        const method = session({
            allowUnsafeEphemeralStoreOffLocalnet: true,
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'devnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        });
        const result = await method.request!({
            credential: {} as never,
            request: { cap: '1000000', currency: 'USDC', operator: '', recipient: '' },
        });
        expect(result.recentBlockhash).toBeUndefined();
        expect(globalThis.fetch).not.toHaveBeenCalled();
    });
});

// ── verify() — open ─────────────────────────────────────────────────────

describe('session() verify() open', () => {
    test('open without transaction trusts channelId+deposit', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';

        const receipt = await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000000',
                mode: 'push',
                signature: 'sig-1',
            }),
            request: {} as never,
        });

        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe('sig-1');
        const stored = await store.getChannel(channelId);
        expect(stored?.deposit).toBe(1_000_000n);
        expect(stored?.cumulative).toBe(0n);
        expect(stored?.authorizedSigner).toBe(signer.address);
    });

    test('open rejects when mode is not advertised', async () => {
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        });
        const signer = await generateKeyPairSigner();
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: '11111111111111111111111111111111',
                    deposit: '1000',
                    mode: 'pull',
                    signature: 'sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not supported/);
    });

    test('open rejects deposit exceeding cap', async () => {
        const method = session({
            cap: 1_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        });
        const signer = await generateKeyPairSigner();
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: '11111111111111111111111111111111',
                    deposit: '10000',
                    mode: 'push',
                    signature: 'sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/exceeds cap/);
    });
});

// ── verify() — voucher ────────────────────────────────────────────────

describe('session() verify() voucher', () => {
    test('accepted voucher advances watermark', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const voucher = await makeSignedVoucher(signer, channelId, 250n);
        const receipt = await method.verify({
            credential: makeCred({ action: 'voucher', voucher }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(`${channelId}:250`);

        const state = await store.getChannel(channelId);
        expect(state?.cumulative).toBe(250n);
        expect(state?.highestVoucherSignature).toBe(voucher.signature);
    });

    test('rejects voucher for unknown channel', async () => {
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        });
        const signer = await generateKeyPairSigner();
        const voucher = await makeSignedVoucher(signer, '11111111111111111111111111111111', 100n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'voucher', voucher }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not found/);
    });

    test('rejects voucher when cumulative does not increase', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        const first = await makeSignedVoucher(signer, channelId, 100n);
        await method.verify({
            credential: makeCred({ action: 'voucher', voucher: first }),
            request: {} as never,
        });
        const stale = await makeSignedVoucher(signer, channelId, 50n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'voucher', voucher: stale }),
                request: {} as never,
            }),
        ).rejects.toThrow(/cumulative-not-monotonic/);
    });
});

// ── verify() — topUp + close + commit (smoke) ─────────────────────────

describe('session() verify() topUp', () => {
    test('topUp updates deposit', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const receipt = await method.verify({
            credential: makeCred({
                action: 'topUp',
                channelId,
                newDeposit: '5000',
                signature: 'topup-sig',
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe('topup-sig');
        const state = await store.getChannel(channelId);
        expect(state?.deposit).toBe(5_000n);
        expect(state?.usedTopUpSignatures).toEqual(['topup-sig']);

        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId,
                    newDeposit: '9000',
                    signature: 'topup-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/already accepted/);
        expect((await store.getChannel(channelId))?.deposit).toBe(5_000n);
    });

    test('topUp atomically rejects a concurrent duplicate signature', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const topUp = () =>
            method.verify({
                credential: makeCred({ action: 'topUp', channelId, newDeposit: '5000', signature: 'topup-sig' }),
                request: {} as never,
            });
        const results = await Promise.allSettled([topUp(), topUp()]);

        expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
        expect(results.filter(result => result.status === 'rejected')).toHaveLength(1);
        expect((await store.getChannel(channelId))?.deposit).toBe(5_000n);
    });

    test('topUp rejects when below current deposit', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '5000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId,
                    newDeposit: '1000',
                    signature: 'topup-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/must exceed current deposit/);
    });
});

describe('session() verify() close', () => {
    test('close without merchant signer flips close-pending and returns receipt', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(receipt.reference).toBe(channelId);

        const state = await store.getChannel(channelId);
        expect(state?.closeRequestedAt).toBeDefined();
        expect(state?.sealed).toBe(false);
    });

    test('close with final voucher advances watermark', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const finalVoucher = await makeSignedVoucher(signer, channelId, 750n);
        await method.verify({
            credential: makeCred({ action: 'close', channelId, voucher: finalVoucher }),
            request: {} as never,
        });

        const state = await store.getChannel(channelId);
        expect(state?.cumulative).toBe(750n);
        expect(state?.closeRequestedAt).toBeDefined();
    });
});

describe('session() verify() commit', () => {
    test('commit succeeds for a reserved delivery', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const routes = session.routes({
            cap: 1_000_000n,
            currency: 'USDC',
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const reserveReq = new Request('http://localhost/__402/session/deliveries', {
            body: JSON.stringify({ amount: '200', sessionId: channelId }),
            headers: { 'Content-Type': 'application/json' },
            method: 'POST',
        });
        const reserveRes = await routes.deliveries(reserveReq);
        expect(reserveRes.status).toBe(200);
        const directive = (await reserveRes.json()) as { deliveryId: string; sequence: number };
        expect(directive.deliveryId).toBe(`${channelId}:1`);
        expect(directive.sequence).toBe(1);

        const voucher = await makeSignedVoucher(signer, channelId, 150n);
        const receipt = await method.verify({
            credential: makeCred({ action: 'commit', deliveryId: directive.deliveryId, voucher }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        const state = await store.getChannel(channelId);
        expect(state?.cumulative).toBe(150n);
        expect(state?.committedDeliveries.length).toBe(1);
    });
});

// ── routes(): commit endpoint ──────────────────────────────────────────

describe('session.routes()', () => {
    test('deliveries rejects unknown channel', async () => {
        const routes = session.routes({
            cap: 1_000n,
            currency: 'USDC',
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        });
        const res = await routes.deliveries(
            new Request('http://localhost/__402/session/deliveries', {
                body: JSON.stringify({ amount: '10', sessionId: 'ghost' }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        expect(res.status).toBe(400);
    });

    test('commit returns receipt with replay status on idempotent retry', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const routes = session.routes({
            cap: 1_000_000n,
            currency: 'USDC',
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const reserve = await routes.deliveries(
            new Request('http://localhost/__402/session/deliveries', {
                body: JSON.stringify({ amount: '50', sessionId: channelId }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        const { deliveryId } = (await reserve.json()) as { deliveryId: string };
        const voucher = await makeSignedVoucher(signer, channelId, 50n);

        const first = await routes.commit(
            new Request('http://localhost/__402/session/commit', {
                body: JSON.stringify({ deliveryId, voucher }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        const firstBody = (await first.json()) as { status: string; amount: string };
        expect(firstBody.status).toBe('committed');
        expect(firstBody.amount).toBe('50');

        const replay = await routes.commit(
            new Request('http://localhost/__402/session/commit', {
                body: JSON.stringify({ deliveryId, voucher }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        const replayBody = (await replay.json()) as { status: string };
        expect(replayBody.status).toBe('replayed');
    });
});

// ── verify() — open replay semantics ────────────────────────────────────

describe('session() verify() open replay', () => {
    const channelId = '11111111111111111111111111111111';

    function makeMethod(store: ReturnType<typeof createMemorySessionStore>) {
        return session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
    }

    function openCred(authorizedSigner: string) {
        return makeCred({
            action: 'open',
            authorizedSigner,
            channelId,
            deposit: '1000',
            mode: 'push',
            signature: 'open-sig',
        });
    }

    test('replaying an open preserves the voucher watermark', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = makeMethod(store);

        await method.verify({ credential: openCred(signer.address), request: {} as never });
        const voucher = await makeSignedVoucher(signer, channelId, 250n);
        await method.verify({ credential: makeCred({ action: 'voucher', voucher }), request: {} as never });

        const receipt = await method.verify({ credential: openCred(signer.address), request: {} as never });
        expect(receipt.status).toBe('success');

        const state = await store.getChannel(channelId);
        expect(state?.cumulative).toBe(250n);
        expect(state?.highestVoucherSignature).toBe(voucher.signature);
    });

    test('open replay with a different authorizedSigner rejects', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const intruder = await generateKeyPairSigner();
        const method = makeMethod(store);

        await method.verify({ credential: openCred(signer.address), request: {} as never });
        await expect(method.verify({ credential: openCred(intruder.address), request: {} as never })).rejects.toThrow(
            /authorizedSigner/,
        );

        const state = await store.getChannel(channelId);
        expect(state?.authorizedSigner).toBe(signer.address);
    });

    test('open replay on a sealed channel rejects', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = makeMethod(store);

        await method.verify({ credential: openCred(signer.address), request: {} as never });
        await store.markSealed(channelId);

        await expect(method.verify({ credential: openCred(signer.address), request: {} as never })).rejects.toThrow(
            /sealed/,
        );
    });
});

// ── verify() — transactionless push open with rpc ───────────────────────

describe('session() verify() open signature verification', () => {
    const channelId = '11111111111111111111111111111111';

    test('verifies the open signature on-chain when rpc is configured', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const rpc = mockStatusRpc({ 'open-sig': { err: null } });
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            store,
        });

        const receipt = await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(rpc.calls).toContain('open-sig');
        expect(await store.getChannel(channelId)).toBeDefined();
    });

    test('rejects when the open signature is unknown on-chain', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const rpc = mockStatusRpc({});
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            store,
        });

        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'ghost-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not found on-chain/);
        expect(await store.getChannel(channelId)).toBeUndefined();
    });

    test('rejects when the open signature failed on-chain', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const rpc = mockStatusRpc({ 'open-sig': { err: { InstructionError: [0, 'Custom'] } } });
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            store,
        });

        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'open-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/failed on-chain/);
    });
});

// ── verify() — pull open session-id keying (Rust parity) ───────────────

describe('session() verify() pull open keying', () => {
    test('prefers channelId over tokenAccount as the session id', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            modes: ['pull'],
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            pullVoucherStrategy: 'clientVoucher',
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        const tokenAccount = 'So11111111111111111111111111111111111111112';

        await method.verify({
            credential: makeCred({
                action: 'open',
                approvedAmount: '1000',
                authorizedSigner: signer.address,
                channelId,
                mode: 'pull',
                signature: 'sig-1',
                tokenAccount,
            }),
            request: {} as never,
        });

        expect(await store.getChannel(channelId)).toBeDefined();
        expect(await store.getChannel(tokenAccount)).toBeUndefined();
    });
});

// ── verify() — voucher wire compatibility ───────────────────────────────

describe('session() verify() voucher wire compatibility', () => {
    test('accepts the legacy `cumulative` alias and advances the watermark', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const canonical = await makeSignedVoucher(signer, channelId, 250n);
        const aliasVoucher = {
            data: {
                channelId,
                cumulative: '250',
                expiresAt: canonical.data.expiresAt,
            },
            signature: canonical.signature,
        } as unknown as SignedVoucher;

        const receipt = await method.verify({
            credential: makeCred({ action: 'voucher', voucher: aliasVoucher }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        const state = await store.getChannel(channelId);
        expect(state?.cumulative).toBe(250n);
    });

    test('schema accepts the `cumulative` alias and rejects vouchers with neither field', () => {
        const base = {
            action: 'voucher',
            voucher: {
                data: { channelId: '11111111111111111111111111111111', expiresAt: 123 },
                signature: 'sig',
            },
        };
        const withAlias = {
            ...base,
            voucher: { ...base.voucher, data: { ...base.voucher.data, cumulative: '10' } },
        };
        expect(() => Methods.session.schema.credential.payload.parse(withAlias)).not.toThrow();
        expect(() => Methods.session.schema.credential.payload.parse(base)).toThrow(/cumulativeAmount/);
    });

    test('schema rejects expiresAt above JS safe-integer precision with a clear error', () => {
        const payload = {
            action: 'voucher',
            voucher: {
                data: {
                    channelId: '11111111111111111111111111111111',
                    cumulativeAmount: '10',
                    expiresAt: 2 ** 60,
                },
                signature: 'sig',
            },
        };
        expect(() => Methods.session.schema.credential.payload.parse(payload)).toThrow(
            /i64.*safe-integer|safe-integer.*i64/,
        );
    });

    test('verify rejects an unsafe expiresAt with the i64-precision error', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const voucher = {
            data: { channelId, cumulativeAmount: '10', expiresAt: 2 ** 60 },
            signature: 'sig',
        } as unknown as SignedVoucher;
        await expect(
            method.verify({
                credential: makeCred({ action: 'voucher', voucher }),
                request: {} as never,
            }),
        ).rejects.toThrow(/i64/);
    });
});

// ── verify() — topUp hardening ──────────────────────────────────────────

describe('session() verify() topUp hardening', () => {
    const channelId = '11111111111111111111111111111111';

    async function openChannel(method: ReturnType<typeof session>, signer: KeyPairSigner): Promise<void> {
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
    }

    test('topUp rejects when close is pending', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        await openChannel(method, signer);
        await method.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never });

        await expect(
            method.verify({
                credential: makeCred({ action: 'topUp', channelId, newDeposit: '5000', signature: 'topup-sig' }),
                request: {} as never,
            }),
        ).rejects.toThrow(/close is pending/);
    });

    test('topUp rejects on a sealed channel', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        await openChannel(method, signer);
        await store.markSealed(channelId);

        await expect(
            method.verify({
                credential: makeCred({ action: 'topUp', channelId, newDeposit: '5000', signature: 'topup-sig' }),
                request: {} as never,
            }),
        ).rejects.toThrow(/sealed/);
    });

    test('topUp requires transaction bytes when rpc is configured', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const rpc = mockStatusRpc({ 'open-sig': { err: null }, 'topup-sig': { err: null } });
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            store,
        });
        await openChannel(method, signer);

        await expect(
            method.verify({
                credential: makeCred({ action: 'topUp', channelId, newDeposit: '5000', signature: 'topup-sig' }),
                request: {} as never,
            }),
        ).rejects.toThrow(/getTransaction/);
        expect(rpc.calls).not.toContain('topup-sig');
        expect((await store.getChannel(channelId))?.deposit).toBe(1_000n);
    });

    test('topUp rejects when the signature is unknown on-chain', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const rpc = {
            ...mockStatusRpc({ 'open-sig': { err: null } }),
            getTransaction: () => {
                throw new Error('getTransaction should not run for an unknown signature');
            },
        };
        const method = session({
            cap: 5_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            store,
        });
        await openChannel(method, signer);

        await expect(
            method.verify({
                credential: makeCred({ action: 'topUp', channelId, newDeposit: '5000', signature: 'ghost-sig' }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not found on-chain/);
        expect((await store.getChannel(channelId))?.deposit).toBe(1_000n);
    });
});

// ── verify() — close final-voucher monotonicity ─────────────────────────

describe('session() verify() close monotonicity', () => {
    const channelId = '11111111111111111111111111111111';

    async function setupWithWatermark(): Promise<{
        method: ReturnType<typeof session>;
        signer: KeyPairSigner;
        store: ReturnType<typeof createMemorySessionStore>;
        voucher: SignedVoucher;
    }> {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        const voucher = await makeSignedVoucher(signer, channelId, 250n);
        await method.verify({ credential: makeCred({ action: 'voucher', voucher }), request: {} as never });
        return { method, signer, store, voucher };
    }

    test('close rejects a non-monotonic final voucher and does not flip close-pending', async () => {
        const { method, signer, store } = await setupWithWatermark();
        const stale = await makeSignedVoucher(signer, channelId, 100n);

        await expect(
            method.verify({
                credential: makeCred({ action: 'close', channelId, voucher: stale }),
                request: {} as never,
            }),
        ).rejects.toThrow(/cumulative-not-monotonic/);

        const state = await store.getChannel(channelId);
        expect(state?.closeRequestedAt).toBeUndefined();
        expect(state?.cumulative).toBe(250n);
    });

    test('close accepts an idempotent replay of the current highest voucher', async () => {
        const { method, store, voucher } = await setupWithWatermark();

        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId, voucher }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');

        const state = await store.getChannel(channelId);
        expect(state?.closeRequestedAt).toBeDefined();
        expect(state?.cumulative).toBe(250n);
    });

    test('close without a final voucher preserves the current watermark', async () => {
        const { method, store } = await setupWithWatermark();

        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');

        const state = await store.getChannel(channelId);
        expect(state?.closeRequestedAt).toBeDefined();
        expect(state?.cumulative).toBe(250n);
    });
});

// ── verify() — close retry after a failed settlement ────────────────────

describe('session() verify() close retry', () => {
    test('settlement fails clearly before outbox creation when getBlockHeight is unavailable', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        const rpc = {
            getLatestBlockhash: () => ({
                send: async () => ({
                    value: {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        lastValidBlockHeight: 100n,
                    },
                }),
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({
                    context: { slot: 42 },
                    value: sigs.map(() => ({ confirmationStatus: 'confirmed', err: null })),
                }),
            }),
            sendTransaction: () => ({ send: async () => 'unused' }),
        };
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            signer: merchant,
            store,
        });
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                payer: signer.address,
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        await expect(
            method.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never }),
        ).rejects.toThrow(/requires rpc\.getBlockHeight/);
        const state = await store.getChannel(channelId);
        expect(state?.settling).toBeUndefined();
        expect(state?.settlementClaimOwner).toBeUndefined();
        expect(state?.settlementPendingSignature).toBeUndefined();
        expect(state?.settlementPendingWire).toBeUndefined();
    });

    test('an uncertain confirmation retries by rebroadcasting the persisted wire', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        let settleSignature: string | undefined;

        let settlementStatusCalls = 0;
        const sends: string[] = [];
        const rpc = {
            getBlockHeight: () => ({ send: async () => 0n }),
            getLatestBlockhash: () => ({
                send: async () => ({
                    value: {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        lastValidBlockHeight: 0n,
                    },
                }),
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => {
                    if (
                        settleSignature !== undefined &&
                        sigs.includes(settleSignature) &&
                        settlementStatusCalls++ === 0
                    ) {
                        throw new Error('status RPC unavailable');
                    }
                    return {
                        context: { slot: 42 },
                        value: sigs.map(() => ({ confirmationStatus: 'confirmed', err: null })),
                    };
                },
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    settleSignature = signedWireSignature(wire);
                    return settleSignature;
                },
            }),
        };

        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            signer: merchant,
            store,
        });

        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                payer: signer.address,
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        // The broadcast succeeded but confirmation is uncertain. The outbox
        // retains the exact signed transaction for idempotent recovery.
        await expect(
            method.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never }),
        ).rejects.toThrow(/status RPC unavailable/);
        let state = await store.getChannel(channelId);
        expect(state?.closeRequestedAt).toBeDefined();
        expect(state?.sealed).toBe(false);
        expect(state?.settlementPendingLastValidBlockHeight).toBe(0n);
        expect(state?.settlementPendingSignature).toBe(settleSignature);
        expect(state?.settlementPendingWire).toBe(sends[0]);
        expect(state?.settling).toBe(false);
        expect(state?.settledSignature).toBeUndefined();
        expect(sends).toHaveLength(1);

        // Retry rebroadcasts the exact same signed transaction, never a newly
        // built transaction with a different signature.
        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(sends).toHaveLength(2);
        expect(new Set(sends).size).toBe(1);
        state = await store.getChannel(channelId);
        expect(state?.sealed).toBe(true);
        expect(state?.settlementPendingLastValidBlockHeight).toBeUndefined();
        expect(state?.settlementPendingSignature).toBeUndefined();
        expect(state?.settlementPendingWire).toBeUndefined();
        expect(state?.settling).toBe(false);
        expect(state?.settledSignature).toBe(settleSignature);

        // A third close on the sealed channel rejects.
        await expect(
            method.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never }),
        ).rejects.toThrow(/sealed/);
    });

    test('a send error still seals when the persisted signature is already confirmed', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        const sends: string[] = [];
        const rpc = {
            getBlockHeight: () => ({ send: async () => 0n }),
            getLatestBlockhash: () => ({
                send: async () => ({
                    value: {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        lastValidBlockHeight: 100n,
                    },
                }),
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({
                    context: { slot: 42 },
                    value: sigs.map(() => ({ confirmationStatus: 'confirmed', err: null })),
                }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    throw new Error('already processed');
                },
            }),
        };
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            signer: merchant,
            store,
        });
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                payer: signer.address,
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(sends).toHaveLength(1);
        const state = await store.getChannel(channelId);
        expect(state?.sealed).toBe(true);
        expect(state?.settledSignature).toBe(signedWireSignature(sends[0]!));
        expect(state?.settlementPendingLastValidBlockHeight).toBeUndefined();
        expect(state?.settlementPendingSignature).toBeUndefined();
        expect(state?.settlementPendingWire).toBeUndefined();
    });

    test('an expired unsent outbox is retired and rebuilt after restart', async () => {
        const durableStore = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        const sends: string[] = [];
        let blockhashCalls = 0;
        let crashBeforeSend = true;
        let phase: 'crash' | 'expired' | 'fresh' = 'crash';
        const crashingStore: SessionStore = {
            ...durableStore,
            async updateChannel(id, mutator) {
                const previous = await durableStore.getChannel(id);
                const next = await durableStore.updateChannel(id, mutator);
                if (
                    crashBeforeSend &&
                    previous?.settlementPendingWire === undefined &&
                    next.settlementPendingWire !== undefined
                ) {
                    crashBeforeSend = false;
                    throw new Error('simulated crash after outbox persistence');
                }
                return next;
            },
        };
        const rpc = {
            getLatestBlockhash: () => ({
                send: async () => {
                    blockhashCalls += 1;
                    return {
                        value: {
                            blockhash:
                                blockhashCalls === 1
                                    ? 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N'
                                    : '11111111111111111111111111111111',
                            lastValidBlockHeight: blockhashCalls === 1 ? 100n : 200n,
                        },
                    };
                },
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({
                    context: { slot: 42 },
                    value: sigs.map(() =>
                        phase === 'expired' ? null : { confirmationStatus: 'confirmed', err: null },
                    ),
                }),
            }),
            getBlockHeight: () => ({ send: async () => 101n }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    if (phase === 'expired') throw new Error('blockhash not found');
                    return signedWireSignature(wire);
                },
            }),
        };
        const createMethod = (store: SessionStore) =>
            session({
                cap: 1_000_000n,
                currency: 'USDC',
                decimals: 6,
                network: 'localnet',
                operator: OPERATOR,
                pricing: {},
                recipient: RECIPIENT,
                rpc: rpc as never,
                settlementConfirmation: { pollIntervalMs: 1, timeoutMs: 20 },
                signer: merchant,
                store,
            });
        const crashedMethod = createMethod(crashingStore);
        await crashedMethod.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                payer: signer.address,
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        await expect(
            crashedMethod.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never }),
        ).rejects.toThrow(/simulated crash/);
        const pending = await durableStore.getChannel(channelId);
        expect(pending?.settlementPendingSignature).toBeDefined();
        expect(pending?.settlementPendingWire).toBeDefined();
        expect(pending?.settlementPendingLastValidBlockHeight).toBe(100n);
        expect(sends).toHaveLength(0);
        expect(blockhashCalls).toBe(1);

        const restartedMethod = createMethod(durableStore);
        phase = 'expired';
        await expect(
            restartedMethod.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never }),
        ).rejects.toThrow(/timed out/);
        expect(sends).toEqual([pending?.settlementPendingWire]);
        const recovered = await durableStore.getChannel(channelId);
        expect(recovered?.sealed).toBe(false);
        expect(recovered?.settlementPendingLastValidBlockHeight).toBeUndefined();
        expect(recovered?.settlementPendingSignature).toBeUndefined();
        expect(recovered?.settlementPendingWire).toBeUndefined();

        phase = 'fresh';
        const receipt = await restartedMethod.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(sends).toHaveLength(2);
        expect(sends[0]).toBe(pending?.settlementPendingWire);
        expect(sends[1]).not.toBe(pending?.settlementPendingWire);
        expect(blockhashCalls).toBe(2);
        const sealed = await durableStore.getChannel(channelId);
        expect(sealed?.sealed).toBe(true);
        expect(sealed?.settledSignature).toBe(signedWireSignature(sends[1]!));
        expect(sealed?.settlementPendingLastValidBlockHeight).toBeUndefined();
        expect(sealed?.settlementPendingSignature).toBeUndefined();
        expect(sealed?.settlementPendingWire).toBeUndefined();
    });

    test('a definite on-chain failure clears the pending signature for a fresh retry', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        const failedSignature = 'FailedSig11111111111111111111111111111111111111111111111111111111';
        let retrySignature: string | undefined;
        const sends: string[] = [];
        const rpc = {
            getBlockHeight: () => ({ send: async () => 0n }),
            getLatestBlockhash: () => ({
                send: async () => ({
                    value: {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        lastValidBlockHeight: 0n,
                    },
                }),
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({
                    context: { slot: 42 },
                    value: sigs.map(signature =>
                        signature === failedSignature
                            ? { confirmationStatus: 'confirmed', err: { InstructionError: [0, 'Custom'] } }
                            : { confirmationStatus: 'confirmed', err: null },
                    ),
                }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    retrySignature = signedWireSignature(wire);
                    return retrySignature;
                },
            }),
        };
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            signer: merchant,
            store,
        });
        await store.updateChannel(channelId, () => ({
            authorizedSigner: signer.address,
            channelId,
            closeRequestedAt: 1n,
            committedDeliveries: [],
            cumulative: 0n,
            deposit: 1_000n,
            nextDeliverySequence: 0n,
            operator: signer.address,
            pendingDeliveries: [],
            sealed: false,
            settlementPendingSignature: failedSignature,
        }));

        await expect(
            method.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never }),
        ).rejects.toThrow(/failed on-chain/);
        let state = await store.getChannel(channelId);
        expect(state?.settlementPendingSignature).toBeUndefined();
        expect(state?.settling).toBe(false);
        expect(state?.sealed).toBe(false);
        expect(sends).toHaveLength(0);

        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        state = await store.getChannel(channelId);
        expect(state?.sealed).toBe(true);
        expect(state?.settledSignature).toBe(retrySignature);
        expect(sends).toHaveLength(1);
    });

    test('restart recovery re-confirms pending signatures and only takes over stale claim-only leases', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const pendingChannelId = '11111111111111111111111111111111';
        const claimOnlyChannelId = OPERATOR;
        const pendingSignature = 'PendingSig1111111111111111111111111111111111111111111111111111111';
        const sends: string[] = [];
        const rpc = {
            getBlockHeight: () => ({ send: async () => 0n }),
            getLatestBlockhash: () => ({
                send: async () => ({
                    value: {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        lastValidBlockHeight: 0n,
                    },
                }),
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({
                    context: { slot: 42 },
                    value: sigs.map(() => ({ confirmationStatus: 'confirmed', err: null })),
                }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    return signedWireSignature(wire);
                },
            }),
        };
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            signer: merchant,
            store,
        });
        const restartedState = (channelId: string): ChannelState => ({
            authorizedSigner: signer.address,
            channelId,
            closeRequestedAt: 1n,
            committedDeliveries: [],
            cumulative: 0n,
            deposit: 1_000n,
            nextDeliverySequence: 0n,
            operator: signer.address,
            pendingDeliveries: [],
            sealed: false,
            settlementClaimExpiresAt: BigInt(Date.now() + 60_000),
            settlementClaimOwner: 'crashed-instance',
            settling: true,
        });
        await store.updateChannel(pendingChannelId, () => ({
            ...restartedState(pendingChannelId),
            settlementPendingSignature: pendingSignature,
        }));
        await store.updateChannel(claimOnlyChannelId, () => restartedState(claimOnlyChannelId));

        const recovered = await method.verify({
            credential: makeCred({ action: 'close', channelId: pendingChannelId }),
            request: {} as never,
        });
        expect(recovered.status).toBe('success');
        expect((await store.getChannel(pendingChannelId))?.settledSignature).toBe(pendingSignature);
        expect(sends).toHaveLength(0);

        const blocked = await method.verify({
            credential: makeCred({ action: 'close', channelId: claimOnlyChannelId }),
            request: {} as never,
        });
        expect(blocked.status).toBe('success');
        expect((await store.getChannel(claimOnlyChannelId))?.sealed).toBe(false);
        expect(sends).toHaveLength(0);

        await store.updateChannel(claimOnlyChannelId, current => ({
            ...current!,
            settlementClaimExpiresAt: 0n,
        }));
        const takenOver = await method.verify({
            credential: makeCred({ action: 'close', channelId: claimOnlyChannelId }),
            request: {} as never,
        });
        expect(takenOver.status).toBe('success');
        expect((await store.getChannel(claimOnlyChannelId))?.sealed).toBe(true);
        expect(sends).toHaveLength(1);
    });

    test('concurrent closes broadcast once and seal only after confirmation', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        let settleSignature: string | undefined;
        const sends: string[] = [];
        let releaseConfirmation!: () => void;
        let secondStatusRequested!: () => void;
        let statusRequested!: () => void;
        let statusRequests = 0;
        const confirmationGate = new Promise<void>(resolve => {
            releaseConfirmation = resolve;
        });
        const statusRequest = new Promise<void>(resolve => {
            statusRequested = resolve;
        });
        const secondStatusRequest = new Promise<void>(resolve => {
            secondStatusRequested = resolve;
        });
        const rpc = {
            getBlockHeight: () => ({ send: async () => 0n }),
            getLatestBlockhash: () => ({
                send: async () => ({
                    value: {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                        lastValidBlockHeight: 0n,
                    },
                }),
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => {
                    if (settleSignature !== undefined && sigs.includes(settleSignature)) {
                        statusRequested();
                        statusRequests += 1;
                        if (statusRequests === 2) secondStatusRequested();
                        await confirmationGate;
                    }
                    return {
                        context: { slot: 42 },
                        value: sigs.map(() => ({ confirmationStatus: 'confirmed', err: null })),
                    };
                },
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    settleSignature = signedWireSignature(wire);
                    return settleSignature;
                },
            }),
        };
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            signer: merchant,
            store,
        });

        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                payer: signer.address,
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const requestAbort = new AbortController();
        const firstClose = method.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: new Request('https://api.test/session/close', { signal: requestAbort.signal }) as never,
        });
        await statusRequest;

        let state = await store.getChannel(channelId);
        expect(state?.settlementPendingSignature).toBe(settleSignature);
        expect(state?.settlementPendingWire).toBe(sends[0]);
        expect(state?.settling).toBe(true);
        expect(state?.sealed).toBe(false);
        expect(state?.settledSignature).toBeUndefined();
        requestAbort.abort();

        const secondClose = method.verify({
            credential: makeCred({ action: 'close', channelId }),
            request: {} as never,
        });
        await secondStatusRequest;
        expect(sends).toHaveLength(2);
        expect(new Set(sends).size).toBe(1);

        releaseConfirmation();
        const [firstReceipt, secondReceipt] = await Promise.all([firstClose, secondClose]);
        expect(firstReceipt.status).toBe('success');
        expect(secondReceipt.status).toBe('success');
        state = await store.getChannel(channelId);
        expect(state?.settlementPendingSignature).toBeUndefined();
        expect(state?.settling).toBe(false);
        expect(state?.sealed).toBe(true);
        expect(state?.settledSignature).toBe(settleSignature);
        expect(sends).toHaveLength(2);
        expect(new Set(sends).size).toBe(1);
    });

    test('close refuses to settle when the channel payer (refund destination) was not recorded', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        const rpc = {
            getBlockHeight: () => ({ send: async () => 0n }),
            getLatestBlockhash: () => ({
                send: async () => ({
                    value: { blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N', lastValidBlockHeight: 0n },
                }),
            }),
            getSignatureStatuses: (sigs: readonly string[]) => ({
                send: async () => ({
                    context: { slot: 42 },
                    value: sigs.map(() => ({ confirmationStatus: 'confirmed', err: null })),
                }),
            }),
            sendTransaction: () => ({ send: async () => 'Sig' }),
        };
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            rpc: rpc as never,
            signer: merchant,
            store,
        });
        // Push open with NO payer field → no refund destination recorded.
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        // The settle must refuse rather than refund the merchant (args.recipient).
        await expect(
            method.verify({ credential: makeCred({ action: 'close', channelId }), request: {} as never }),
        ).rejects.toThrow(/refund destination/);
    });
});

// ── verify() — commit replay re-verification ────────────────────────────

describe('session() verify() commit replay', () => {
    test('replaying a committed delivery re-verifies the voucher signature', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
            store,
        });
        const channelId = '11111111111111111111111111111111';
        const forgedSignature = getBase58Decoder().decode(new Uint8Array(64).fill(0xaa));

        // Seed a channel whose committed delivery carries a forged
        // signature — a replay must fail signature re-verification.
        const seeded: ChannelState = {
            authorizedSigner: signer.address,
            channelId,
            closeRequestedAt: undefined,
            committedDeliveries: [
                { amount: 50n, cumulative: 50n, deliveryId: 'd-1', voucherSignature: forgedSignature },
            ],
            cumulative: 50n,
            deposit: 1_000n,
            sealed: false,
            highestVoucherExpiresAt: undefined,
            highestVoucherSignature: undefined,
            nextDeliverySequence: 1n,
            operator: undefined,
            pendingDeliveries: [],
        };
        await store.updateChannel(channelId, () => seeded);

        const forgedVoucher: SignedVoucher = {
            data: { channelId, cumulativeAmount: '50', expiresAt: FAR_FUTURE },
            signature: forgedSignature,
        };
        await expect(
            method.verify({
                credential: makeCred({ action: 'commit', deliveryId: 'd-1', voucher: forgedVoucher }),
                request: {} as never,
            }),
        ).rejects.toThrow(/invalid-signature/);
    });
});

// ── session() + session.routes() share a default store ──────────────────

describe('session() default store sharing', () => {
    test('routes() built from the same parameters sees channels opened via verify()', async () => {
        const signer = await generateKeyPairSigner();
        const parameters: session.Parameters = {
            cap: 1_000_000n,
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        };
        const method = session(parameters);
        const routes = session.routes(parameters);
        const channelId = '11111111111111111111111111111111';

        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });

        const res = await routes.deliveries(
            new Request('http://localhost/__402/session/deliveries', {
                body: JSON.stringify({ amount: '100', sessionId: channelId }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        expect(res.status).toBe(200);
        const directive = (await res.json()) as { deliveryId: string };
        expect(directive.deliveryId).toBe(`${channelId}:1`);
    });
});
