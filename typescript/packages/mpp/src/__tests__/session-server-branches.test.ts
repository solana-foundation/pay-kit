/**
 * Branch-coverage tests for the server-side Session method
 * (server/Session.ts).
 *
 * session-server.test.ts already covers the happy paths. This suite fills
 * the remaining branches:
 *   - the session() factory config validation (cap, signers, splits, modes,
 *     openTxSubmitter, pricing)
 *   - the closeDelayMs lifecycle wiring (touch on open/voucher, remove on
 *     close)
 *   - handler error paths (open payload validation, topUp/close/commit
 *     rejections, deposit-zero, unknown-channel)
 *   - the session.routes() request-body validation (400s)
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { generateKeyPairSigner, getBase58Decoder, type KeyPairSigner } from '@solana/kit';

import { session } from '../server/Session.js';
import { createMemorySessionStore } from '../server/session/store.js';
import type { SignedVoucher, VoucherData } from '../shared/session-types.js';
import { encodeVoucherMessage } from '../shared/voucher.js';

const OPERATOR = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const RECIPIENT = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';
const CHANNEL_ID = '11111111111111111111111111111111';
const FAR_FUTURE = Math.floor(Date.now() / 1000) + 3600;

/** Mock RPC whose getSignatureStatuses returns the given lookup result. */
function mockStatusRpc(statuses: Record<string, { err: unknown } | null | undefined>) {
    return {
        getSignatureStatuses: (sigs: readonly string[]) => ({
            send: async () => ({ value: sigs.map(sig => statuses[sig] ?? null) }),
        }),
    };
}

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

function baseParams(overrides: Record<string, unknown> = {}) {
    return {
        cap: 1_000_000n,
        currency: 'USDC',
        decimals: 6,
        network: 'devnet',
        operator: OPERATOR,
        pricing: {},
        recipient: RECIPIENT,
        ...overrides,
    } as Parameters<typeof session>[0];
}

/** Credential with no challenge.id (and no externalId) — flips the optional
 * `challengeId` / `externalId` receipt spreads to their absent branch. */
function makeBareCred<P>(payload: P) {
    return {
        challenge: {
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: { cap: '1000000', currency: 'USDC', operator: OPERATOR, recipient: RECIPIENT },
        },
        payload,
    } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];
}

async function openPushChannel(
    method: ReturnType<typeof session>,
    signer: KeyPairSigner,
    deposit = '1000',
    channelId = CHANNEL_ID,
) {
    await method.verify({
        credential: makeCred({
            action: 'open',
            authorizedSigner: signer.address,
            channelId,
            deposit,
            mode: 'push',
            signature: 'open-sig',
        }),
        request: {} as never,
    });
}

// ── session() factory config validation ─────────────────────────────────

describe('session() config validation', () => {
    test('rejects a non-positive cap', () => {
        expect(() => session(baseParams({ cap: 0n }))).toThrow(/cap must be positive/);
    });

    test('rejects a signer that is not a transaction partial signer', () => {
        expect(() => session(baseParams({ signer: { address: OPERATOR } as never }))).toThrow(
            /signer must implement signTransactions/,
        );
    });

    test('rejects a paymentChannelPayerSigner that is not a transaction partial signer', () => {
        expect(() => session(baseParams({ paymentChannelPayerSigner: { address: OPERATOR } as never }))).toThrow(
            /paymentChannelPayerSigner must implement signTransactions/,
        );
    });

    test('rejects more than 8 splits', () => {
        const splits = Array.from({ length: 9 }, () => ({ bps: 100, recipient: RECIPIENT }));
        expect(() => session(baseParams({ splits }))).toThrow(/splits cannot exceed 8/);
    });

    test('rejects pull mode without a pullVoucherStrategy', () => {
        expect(() => session(baseParams({ modes: ['pull'] }))).toThrow(/pullVoucherStrategy is required/);
    });

    test('rejects an invalid openTxSubmitter', () => {
        expect(() => session(baseParams({ openTxSubmitter: 'nobody' as never }))).toThrow(
            /openTxSubmitter must be 'client' or 'server'/,
        );
    });

    test('rejects a non-positive pricing.perDelivery', () => {
        expect(() => session(baseParams({ pricing: { perDelivery: 0n } }))).toThrow(
            /pricing.perDelivery must be positive/,
        );
    });

    test('accepts a valid partial signer and a full split set', async () => {
        const signer = await generateKeyPairSigner();
        const method = session(
            baseParams({
                signer,
                paymentChannelPayerSigner: signer,
                minVoucherDelta: 10n,
                splits: [{ bps: 10000, recipient: RECIPIENT }],
                pricing: { perDelivery: 100n },
            }),
        );
        expect(method.verify).toBeTypeOf('function');
    });
});

// ── open payload validation branches ────────────────────────────────────

describe('session() verify() open payload validation', () => {
    test('push open without transaction or channelId is rejected', async () => {
        const method = session(baseParams());
        const signer = await generateKeyPairSigner();
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    deposit: '100',
                    mode: 'push',
                    signature: 'sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/missing transaction or channelId/);
    });

    test('open with a zero deposit is rejected', async () => {
        const method = session(baseParams());
        const signer = await generateKeyPairSigner();
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: CHANNEL_ID,
                    deposit: '0',
                    mode: 'push',
                    signature: 'sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/deposit must be greater than zero/);
    });

    test('open replay from a different authorizedSigner is rejected', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store }));
        const signer = await generateKeyPairSigner();
        const intruder = await generateKeyPairSigner();
        await openPushChannel(method, signer);
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: intruder.address,
                    channelId: CHANNEL_ID,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'open-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/does not match existing channel/);
    });

    test('unknown session action is rejected', async () => {
        const method = session(baseParams());
        await expect(
            method.verify({
                credential: makeCred({ action: 'teleport' } as never),
                request: {} as never,
            }),
        ).rejects.toThrow(/Unknown session action/);
    });
});

// ── closeDelayMs lifecycle wiring ───────────────────────────────────────

describe('session() with closeDelayMs arms the lifecycle', () => {
    test('open/voucher/close drive the lifecycle without a signer (idle-close disabled inside handler)', async () => {
        const store = createMemorySessionStore();
        // closeDelayMs > 0 constructs a Lifecycle; without a signer/rpc the
        // idle-close callback returns early, but touch/removeChannel still run.
        const method = session(baseParams({ store, closeDelayMs: 50_000 }));
        const signer = await generateKeyPairSigner();

        await openPushChannel(method, signer);
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 200n);
        await method.verify({
            credential: makeCred({ action: 'voucher', voucher }),
            request: {} as never,
        });
        const closeReceipt = await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID }),
            request: {} as never,
        });
        expect(closeReceipt.status).toBe('success');
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.closeRequestedAt).toBeDefined();
    });
});

// ── voucher rejection branches ──────────────────────────────────────────

describe('session() verify() voucher rejections', () => {
    test('a voucher below the minVoucherDelta is rejected', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store, minVoucherDelta: 500n }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer);
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 100n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'voucher', voucher }),
                request: {} as never,
            }),
        ).rejects.toThrow();
    });

    test('an idempotent voucher replay keeps the watermark and returns success', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer);
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 300n);
        await method.verify({
            credential: makeCred({ action: 'voucher', voucher }),
            request: {} as never,
        });
        const replay = await method.verify({
            credential: makeCred({ action: 'voucher', voucher }),
            request: {} as never,
        });
        expect(replay.reference).toBe(`${CHANNEL_ID}:300`);
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.cumulative).toBe(300n);
    });
});

// ── topUp error branches ────────────────────────────────────────────────

describe('session() verify() topUp errors', () => {
    test('topUp above cap is rejected', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ cap: 1_000n, store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer, '500');
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: CHANNEL_ID,
                    newDeposit: '2000',
                    signature: 'topup-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/exceeds cap/);
    });

    test('topUp on an unknown channel is rejected', async () => {
        const method = session(baseParams());
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: 'ghost',
                    newDeposit: '500',
                    signature: 'topup-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not found/);
    });

    test('topUp not exceeding the current deposit is rejected', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer, '1000');
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: CHANNEL_ID,
                    newDeposit: '1000',
                    signature: 'topup-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/must exceed current deposit/);
    });

    test('topUp succeeds and updates the deposit', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ cap: 5_000_000n, store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer, '1000');
        const receipt = await method.verify({
            credential: makeCred({
                action: 'topUp',
                channelId: CHANNEL_ID,
                newDeposit: '2000',
                signature: 'topup-sig',
            }),
            request: {} as never,
        });
        expect(receipt.reference).toBe('topup-sig');
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.deposit).toBe(2000n);
    });
});

// ── close error / replay branches ───────────────────────────────────────

describe('session() verify() close branches', () => {
    test('close on an unknown channel is rejected', async () => {
        const method = session(baseParams());
        await expect(
            method.verify({
                credential: makeCred({ action: 'close', channelId: 'ghost' }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not found/);
    });

    test('a second close without an on-chain settle is re-drivable', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer);
        await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID }),
            request: {} as never,
        });
        // No merchant signer configured, so settledSignature stays undefined:
        // the retry is allowed to proceed rather than throwing.
        const retry = await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID }),
            request: {} as never,
        });
        expect(retry.status).toBe('success');
    });

    test('close with a stale final voucher (below watermark) is rejected', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer);
        const advance = await makeSignedVoucher(signer, CHANNEL_ID, 500n);
        await method.verify({
            credential: makeCred({ action: 'voucher', voucher: advance }),
            request: {} as never,
        });
        const stale = await makeSignedVoucher(signer, CHANNEL_ID, 100n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'close', channelId: CHANNEL_ID, voucher: stale }),
                request: {} as never,
            }),
        ).rejects.toThrow();
    });

    test('close with a replayed final voucher records close-pending without moving the watermark', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer);
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 400n);
        await method.verify({
            credential: makeCred({ action: 'voucher', voucher }),
            request: {} as never,
        });
        await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID, voucher }),
            request: {} as never,
        });
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.cumulative).toBe(400n);
        expect(state?.closeRequestedAt).toBeDefined();
    });
});

// ── commit branches ─────────────────────────────────────────────────────

describe('session() verify() commit branches', () => {
    test('commit for a delivery that was never reserved is rejected', async () => {
        const store = createMemorySessionStore();
        const method = session(baseParams({ store }));
        const signer = await generateKeyPairSigner();
        await openPushChannel(method, signer);
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 100n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'commit', deliveryId: 'never-made', voucher }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not found/);
    });
});

// ── session.routes() request-body validation ────────────────────────────

function routesFor(store: ReturnType<typeof createMemorySessionStore>) {
    return session.routes(baseParams({ store }) as unknown as Parameters<typeof session.routes>[0]);
}

function postJson(url: string, body: unknown): Request {
    return new Request(url, {
        body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json' },
        method: 'POST',
    });
}

describe('session.routes() request validation', () => {
    test('routes() throws when cap is missing', () => {
        expect(() => session.routes({ currency: 'USDC' } as unknown as Parameters<typeof session.routes>[0])).toThrow(
            /cap is required/,
        );
    });

    test('deliveries rejects a non-JSON / non-object body', async () => {
        const routes = routesFor(createMemorySessionStore());
        const req = new Request('http://localhost/__402/session/deliveries', {
            body: 'not-json',
            headers: { 'Content-Type': 'application/json' },
            method: 'POST',
        });
        const res = await routes.deliveries(req);
        expect(res.status).toBe(400);
    });

    test('deliveries rejects a missing sessionId', async () => {
        const routes = routesFor(createMemorySessionStore());
        const res = await routes.deliveries(postJson('http://localhost/d', { amount: '10' }));
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ error: expect.stringMatching(/sessionId required/) });
    });

    test('deliveries rejects a zero amount', async () => {
        const routes = routesFor(createMemorySessionStore());
        const res = await routes.deliveries(postJson('http://localhost/d', { amount: '0', sessionId: CHANNEL_ID }));
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ error: expect.stringMatching(/amount must be positive/) });
    });

    test('commit rejects a non-object body', async () => {
        const routes = routesFor(createMemorySessionStore());
        const req = new Request('http://localhost/__402/session/commit', {
            body: 'nope',
            headers: { 'Content-Type': 'application/json' },
            method: 'POST',
        });
        const res = await routes.commit(req);
        expect(res.status).toBe(400);
    });

    test('commit rejects a missing deliveryId', async () => {
        const routes = routesFor(createMemorySessionStore());
        const res = await routes.commit(postJson('http://localhost/c', { voucher: {} }));
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ error: expect.stringMatching(/deliveryId required/) });
    });

    test('commit rejects a missing voucher', async () => {
        const routes = routesFor(createMemorySessionStore());
        const res = await routes.commit(postJson('http://localhost/c', { deliveryId: 'x' }));
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ error: expect.stringMatching(/voucher required/) });
    });

    test('commit surfaces a handler error as a 400', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer);
        const routes = routesFor(store);
        // A voucher for a delivery that was never reserved -> handler throws.
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 100n);
        const res = await routes.commit(postJson('http://localhost/c', { deliveryId: 'ghost', voucher }));
        expect(res.status).toBe(400);
    });

    test('deliveries succeeds and reserves capacity', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        const routes = routesFor(store);
        const res = await routes.deliveries(
            postJson('http://localhost/d', {
                amount: '200',
                commitUrl: 'http://localhost/c',
                proof: 'proof-blob',
                sessionId: CHANNEL_ID,
            }),
        );
        expect(res.status).toBe(200);
        const directive = (await res.json()) as { commitUrl?: string; proof?: string };
        expect(directive.commitUrl).toBe('http://localhost/c');
        expect(directive.proof).toBe('proof-blob');
    });
});

// ── request() challenge builder: all optional fields present ─────────────

describe('session() request() optional-field branches', () => {
    let originalFetch: typeof globalThis.fetch;

    beforeEach(() => {
        originalFetch = globalThis.fetch;
        // A fetch that rejects exercises the catch branch in request() (the
        // blockhash prefetch is non-fatal), leaving recentBlockhash unset.
        globalThis.fetch = vi.fn(async () => {
            throw new Error('rpc down');
        }) as typeof globalThis.fetch;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    test('emits every optional field when configured and requested', async () => {
        const method = session(
            baseParams({
                minVoucherDelta: 25n,
                modes: ['pull', 'push'],
                programId: '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ',
                pullVoucherStrategy: 'clientVoucher',
                splits: [{ bps: 10000, recipient: RECIPIENT }],
            }),
        );
        const result = await method.request!({
            credential: null,
            request: {
                cap: '1000000',
                currency: 'USDC',
                description: 'weekly plan',
                externalId: 'ext-42',
                operator: '',
                recipient: '',
            } as never,
        });
        expect(result.description).toBe('weekly plan');
        expect(result.externalId).toBe('ext-42');
        expect(result.minVoucherDelta).toBe('25');
        expect(result.programId).toBe('9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ');
        expect(result.splits).toHaveLength(1);
        expect(result.pullVoucherStrategy).toBe('clientVoucher');
        // Prefetch failed (fetch threw), so no blockhash is attached.
        expect(result.recentBlockhash).toBeUndefined();
    });
});

// ── open signature verification against an RPC ──────────────────────────

describe('session() verify() open signature checks', () => {
    test('a confirmed open signature is accepted when an rpc is configured', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store, rpc: mockStatusRpc({ 'good-sig': { err: null } }) as never }));
        const receipt = await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId: CHANNEL_ID,
                deposit: '1000',
                mode: 'push',
                signature: 'good-sig',
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
    });

    test('an unknown open signature is rejected when an rpc is configured', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store, rpc: mockStatusRpc({}) as never }));
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: CHANNEL_ID,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'missing-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not found on-chain/);
    });

    test('an open signature that failed on-chain is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(
            baseParams({
                store,
                rpc: mockStatusRpc({ 'bad-sig': { err: { InstructionError: [0, 'Custom'] } } }) as never,
            }),
        );
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: CHANNEL_ID,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'bad-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/failed on-chain/);
    });
});

// ── topUp against an rpc + close-pending guard ──────────────────────────

describe('session() verify() topUp against rpc', () => {
    test('topUp confirms the signature on-chain and raises the deposit', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        // Open with a no-rpc method so the open assertion is skipped; then
        // top up with an rpc-configured method sharing the same store.
        await openPushChannel(session(baseParams({ cap: 5_000_000n, store })), signer, '1000');
        const method = session(
            baseParams({ cap: 5_000_000n, store, rpc: mockStatusRpc({ 'topup-sig': { err: null } }) as never }),
        );
        const receipt = await method.verify({
            credential: makeCred({
                action: 'topUp',
                channelId: CHANNEL_ID,
                newDeposit: '2000',
                signature: 'topup-sig',
            }),
            request: {} as never,
        });
        expect(receipt.reference).toBe('topup-sig');
    });

    test('topUp is rejected once a close is pending', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ cap: 5_000_000n, store }));
        await openPushChannel(method, signer, '1000');
        await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID }),
            request: {} as never,
        });
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: CHANNEL_ID,
                    newDeposit: '2000',
                    signature: 'topup-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/close is pending/);
    });
});

// ── commit branches: expired / exceeds-reserved / replay ────────────────

async function reserve(
    store: ReturnType<typeof createMemorySessionStore>,
    amount: string,
    expiresAt?: number,
    deliveryId?: string,
) {
    const routes = session.routes(baseParams({ store }) as unknown as Parameters<typeof session.routes>[0]);
    const res = await routes.deliveries(
        new Request('http://localhost/d', {
            body: JSON.stringify({ amount, deliveryId, expiresAt, sessionId: CHANNEL_ID }),
            headers: { 'Content-Type': 'application/json' },
            method: 'POST',
        }),
    );
    return (await res.json()) as { deliveryId: string };
}

describe('session() verify() commit deep branches', () => {
    test('commit whose cumulative exceeds the reserved amount is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        const { deliveryId } = await reserve(store, '50');
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 200n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'commit', deliveryId, voucher }),
                request: {} as never,
            }),
        ).rejects.toThrow(/exceeds reserved amount/);
    });

    test('commit whose cumulative does not advance the watermark is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        const advance = await makeSignedVoucher(signer, CHANNEL_ID, 300n);
        await method.verify({
            credential: makeCred({ action: 'voucher', voucher: advance }),
            request: {} as never,
        });
        const { deliveryId } = await reserve(store, '100');
        const stale = await makeSignedVoucher(signer, CHANNEL_ID, 300n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'commit', deliveryId, voucher: stale }),
                request: {} as never,
            }),
        ).rejects.toThrow(/must exceed watermark/);
    });

    test('an expired delivery cannot be committed', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        // Reserve with an already-past expiry.
        const past = Math.floor(Date.now() / 1000) - 10;
        const { deliveryId } = await reserve(store, '100', past);
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 100n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'commit', deliveryId, voucher }),
                request: {} as never,
            }),
        ).rejects.toThrow(/has expired/);
    });

    test('an idempotent commit replay returns the replayed receipt', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        const { deliveryId } = await reserve(store, '200');
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 150n);
        await method.verify({
            credential: makeCred({ action: 'commit', deliveryId, voucher }),
            request: {} as never,
        });
        // Replay the exact same commit → replayed path, watermark unchanged.
        const replay = await method.verify({
            credential: makeCred({ action: 'commit', deliveryId, voucher }),
            request: {} as never,
        });
        expect(replay.status).toBe('success');
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.cumulative).toBe(150n);
        expect(state?.committedDeliveries).toHaveLength(1);
    });

    test('committing a delivery with a different voucher is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        const { deliveryId } = await reserve(store, '400');
        const first = await makeSignedVoucher(signer, CHANNEL_ID, 100n);
        await method.verify({
            credential: makeCred({ action: 'commit', deliveryId, voucher: first }),
            request: {} as never,
        });
        const different = await makeSignedVoucher(signer, CHANNEL_ID, 200n);
        await expect(
            method.verify({
                credential: makeCred({ action: 'commit', deliveryId, voucher: different }),
                request: {} as never,
            }),
        ).rejects.toThrow(/already committed with a different voucher/);
    });
});

// ── reserveDelivery branches (via routes) ───────────────────────────────

describe('session.routes() deliveries branches', () => {
    test('a delivery exceeding the available deposit is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '100');
        const routes = session.routes(baseParams({ store }) as unknown as Parameters<typeof session.routes>[0]);
        const res = await routes.deliveries(
            new Request('http://localhost/d', {
                body: JSON.stringify({ amount: '500', sessionId: CHANNEL_ID }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ error: expect.stringMatching(/exceeds available deposit/) });
    });

    test('a duplicate deliveryId is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        await reserve(store, '50', undefined, 'dup-1');
        const routes = session.routes(baseParams({ store }) as unknown as Parameters<typeof session.routes>[0]);
        const res = await routes.deliveries(
            new Request('http://localhost/d', {
                body: JSON.stringify({ amount: '50', deliveryId: 'dup-1', sessionId: CHANNEL_ID }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ error: expect.stringMatching(/already exists/) });
    });

    test('a delivery on a close-pending channel is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID }),
            request: {} as never,
        });
        const routes = session.routes(baseParams({ store }) as unknown as Parameters<typeof session.routes>[0]);
        const res = await routes.deliveries(
            new Request('http://localhost/d', {
                body: JSON.stringify({ amount: '50', sessionId: CHANNEL_ID }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        expect(res.status).toBe(400);
        expect(await res.json()).toMatchObject({ error: expect.stringMatching(/close is pending/) });
    });
});

// ── close-and-settle on-chain path (mock rpc + merchant signer) ──────────

function mockSettleRpc() {
    return {
        getLatestBlockhash: () => ({
            send: async () => ({
                value: {
                    blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N',
                    lastValidBlockHeight: 0n,
                },
            }),
        }),
        getSignatureStatuses: (sigs: readonly string[]) => ({
            send: async () => ({ value: sigs.map(() => ({ err: null })) }),
        }),
        sendTransaction: () => ({
            send: async () => 'SettleSig1111111111111111111111111111111111111111111111111111111',
        }),
    };
}

describe('session() verify() close with on-chain settle', () => {
    test('close settles on-chain and threads the externalId through the receipt', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const merchant = await generateKeyPairSigner();
        const method = session(baseParams({ store, rpc: mockSettleRpc() as never, signer: merchant }));

        // Open with a payer so the refund destination is recorded.
        await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId: CHANNEL_ID,
                deposit: '1000',
                mode: 'push',
                payer: signer.address,
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 250n);
        await method.verify({
            credential: makeCred({ action: 'voucher', voucher }),
            request: {} as never,
        });

        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID }, { externalId: 'ext-close' }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        expect(receipt.externalId).toBe('ext-close');
        // The on-chain signature is used as the receipt reference.
        expect(receipt.reference).toMatch(/^SettleSig/);
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.finalized).toBe(true);
    });
});

// ── receipts without a challenge id / externalId (absent-spread branch) ──

describe('session() receipts with a bare credential', () => {
    test('open/voucher/topUp/commit/close all succeed without a challenge id', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ cap: 5_000_000n, store }));

        const openReceipt = await method.verify({
            credential: makeBareCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId: CHANNEL_ID,
                deposit: '1000',
                mode: 'push',
                signature: 'open-sig',
            }),
            request: {} as never,
        });
        expect(openReceipt.challengeId).toBeUndefined();
        expect(openReceipt.externalId).toBeUndefined();

        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 200n);
        const voucherReceipt = await method.verify({
            credential: makeBareCred({ action: 'voucher', voucher }),
            request: {} as never,
        });
        expect(voucherReceipt.challengeId).toBeUndefined();

        const topUpReceipt = await method.verify({
            credential: makeBareCred({
                action: 'topUp',
                channelId: CHANNEL_ID,
                newDeposit: '2000',
                signature: 'topup-sig',
            }),
            request: {} as never,
        });
        expect(topUpReceipt.challengeId).toBeUndefined();

        // Reserve + commit through a bare credential.
        const routes = session.routes(baseParams({ store }) as unknown as Parameters<typeof session.routes>[0]);
        const reserveRes = await routes.deliveries(
            new Request('http://localhost/d', {
                body: JSON.stringify({ amount: '100', sessionId: CHANNEL_ID }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        const { deliveryId } = (await reserveRes.json()) as { deliveryId: string };
        const commitVoucher = await makeSignedVoucher(signer, CHANNEL_ID, 250n);
        const commitReceipt = await method.verify({
            credential: makeBareCred({ action: 'commit', deliveryId, voucher: commitVoucher }),
            request: {} as never,
        });
        expect(commitReceipt.challengeId).toBeUndefined();

        const closeReceipt = await method.verify({
            credential: makeBareCred({ action: 'close', channelId: CHANNEL_ID }),
            request: {} as never,
        });
        expect(closeReceipt.challengeId).toBeUndefined();
        expect(closeReceipt.externalId).toBeUndefined();
    });
});

// ── helper / parse error branches ───────────────────────────────────────

describe('session() parse + helper error branches', () => {
    test('open with a non-numeric deposit string is rejected', async () => {
        const method = session(baseParams());
        const signer = await generateKeyPairSigner();
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: CHANNEL_ID,
                    deposit: 'twelve',
                    mode: 'push',
                    signature: 'sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/not an unsigned integer/);
    });

    test('topUp with a deposit above the u64 range is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ cap: 1_000_000n, store }));
        await openPushChannel(method, signer, '1000');
        const overU64 = (1n << 64n).toString();
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'topUp',
                    channelId: CHANNEL_ID,
                    newDeposit: overU64,
                    signature: 'topup-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/outside u64 range/);
    });

    test('routes deliveries throws on a non-numeric amount (parsed before the try)', async () => {
        const routes = session.routes(
            baseParams({ store: createMemorySessionStore() }) as unknown as Parameters<typeof session.routes>[0],
        );
        // parseU64String runs before the try/catch, so the parse error
        // propagates rather than being mapped to a 400.
        await expect(
            routes.deliveries(
                new Request('http://localhost/d', {
                    body: JSON.stringify({ amount: 'lots', sessionId: CHANNEL_ID }),
                    headers: { 'Content-Type': 'application/json' },
                    method: 'POST',
                }),
            ),
        ).rejects.toThrow(/not an unsigned integer/);
    });
});

// ── pull-mode open keying (channelId / tokenAccount fallbacks) ───────────

describe('session() verify() pull open keying branches', () => {
    test('pull open keys on tokenAccount when channelId is absent', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ modes: ['pull'], pullVoucherStrategy: 'clientVoucher', store }));
        const tokenAccount = '22222222222222222222222222222222';
        const receipt = await method.verify({
            credential: makeCred({
                action: 'open',
                approvedAmount: '500',
                authorizedSigner: signer.address,
                mode: 'pull',
                signature: 'pull-sig',
                tokenAccount,
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        const state = await store.getChannel(tokenAccount);
        expect(state?.deposit).toBe(500n);
    });

    test('pull open missing both channelId and tokenAccount is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ modes: ['pull'], pullVoucherStrategy: 'clientVoucher', store }));
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    approvedAmount: '500',
                    authorizedSigner: signer.address,
                    mode: 'pull',
                    signature: 'pull-sig',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/channelId\/tokenAccount required/);
    });

    test('pull open falls back to deposit when approvedAmount is absent', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ modes: ['pull'], pullVoucherStrategy: 'clientVoucher', store }));
        const receipt = await method.verify({
            credential: makeCred({
                action: 'open',
                authorizedSigner: signer.address,
                channelId: CHANNEL_ID,
                deposit: '750',
                mode: 'pull',
                signature: 'pull-sig',
            }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.deposit).toBe(750n);
    });
});

// ── open receipt threads externalId + falls back to channelId reference ──

describe('session() verify() open receipt branches', () => {
    test('open receipt carries the challenge externalId', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        const receipt = await method.verify({
            credential: makeCred(
                {
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: CHANNEL_ID,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'open-sig',
                },
                { externalId: 'ext-open' },
            ),
            request: {} as never,
        });
        expect(receipt.externalId).toBe('ext-open');
        expect(receipt.reference).toBe('open-sig');
    });

    test('open with no signature uses the channelId as the receipt reference', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ modes: ['pull'], pullVoucherStrategy: 'clientVoucher', store }));
        // Pull open without a signature → reference falls back to channelId.
        const receipt = await method.verify({
            credential: makeCred({
                action: 'open',
                approvedAmount: '500',
                authorizedSigner: signer.address,
                channelId: CHANNEL_ID,
                mode: 'pull',
            }),
            request: {} as never,
        });
        expect(receipt.reference).toBe(CHANNEL_ID);
    });
});

// ── externalId threaded through voucher / commit / topUp receipts ────────

describe('session() receipts thread externalId through every action', () => {
    test('voucher, topUp and commit receipts carry the challenge externalId', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ cap: 5_000_000n, store }));
        await openPushChannel(method, signer, '1000');

        const voucher = await makeSignedVoucher(signer, CHANNEL_ID, 200n);
        const voucherReceipt = await method.verify({
            credential: makeCred({ action: 'voucher', voucher }, { externalId: 'ext-v' }),
            request: {} as never,
        });
        expect(voucherReceipt.externalId).toBe('ext-v');

        const topUpReceipt = await method.verify({
            credential: makeCred(
                { action: 'topUp', channelId: CHANNEL_ID, newDeposit: '2000', signature: 'topup-sig' },
                { externalId: 'ext-t' },
            ),
            request: {} as never,
        });
        expect(topUpReceipt.externalId).toBe('ext-t');

        const routes = session.routes(baseParams({ store }) as unknown as Parameters<typeof session.routes>[0]);
        const reserveRes = await routes.deliveries(
            new Request('http://localhost/d', {
                body: JSON.stringify({ amount: '100', sessionId: CHANNEL_ID }),
                headers: { 'Content-Type': 'application/json' },
                method: 'POST',
            }),
        );
        const { deliveryId } = (await reserveRes.json()) as { deliveryId: string };
        const commitVoucher = await makeSignedVoucher(signer, CHANNEL_ID, 250n);
        const commitReceipt = await method.verify({
            credential: makeCred({ action: 'commit', deliveryId, voucher: commitVoucher }, { externalId: 'ext-c' }),
            request: {} as never,
        });
        expect(commitReceipt.externalId).toBe('ext-c');
    });
});

// ── close with an advancing final voucher (accepted verdict) ────────────

describe('session() verify() close accepts an advancing final voucher', () => {
    test('close records the advancing voucher watermark', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ store }));
        await openPushChannel(method, signer, '1000');
        // No prior voucher: the close voucher itself advances the watermark.
        const finalVoucher = await makeSignedVoucher(signer, CHANNEL_ID, 600n);
        const receipt = await method.verify({
            credential: makeCred({ action: 'close', channelId: CHANNEL_ID, voucher: finalVoucher }),
            request: {} as never,
        });
        expect(receipt.status).toBe('success');
        const state = await store.getChannel(CHANNEL_ID);
        expect(state?.cumulative).toBe(600n);
        expect(state?.closeRequestedAt).toBeDefined();
    });
});

// ── openTxSubmitter='server' requires an rpc client ─────────────────────

describe('session() verify() open server-submit without rpc', () => {
    test('a transaction-backed open with openTxSubmitter=server but no rpc is rejected', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const method = session(baseParams({ openTxSubmitter: 'server', store }));
        await expect(
            method.verify({
                credential: makeCred({
                    action: 'open',
                    authorizedSigner: signer.address,
                    channelId: CHANNEL_ID,
                    deposit: '1000',
                    mode: 'push',
                    signature: 'open-sig',
                    transaction: 'AA==',
                }),
                request: {} as never,
            }),
        ).rejects.toThrow(/requires an rpc client/);
    });
});

// ── request() without configured decimals (absent-spread branch) ────────

describe('session() request() without decimals', () => {
    let originalFetch: typeof globalThis.fetch;
    beforeEach(() => {
        originalFetch = globalThis.fetch;
        globalThis.fetch = vi.fn(async () => {
            throw new Error('rpc down');
        }) as typeof globalThis.fetch;
    });
    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    test('omits decimals from the challenge when the config has none', async () => {
        const method = session({
            cap: 1_000_000n,
            currency: 'USDC',
            network: 'devnet',
            operator: OPERATOR,
            pricing: {},
            recipient: RECIPIENT,
        });
        const result = await method.request!({
            credential: null,
            request: { cap: '1000000', currency: 'USDC', operator: '', recipient: '' },
        });
        expect(result.decimals).toBeUndefined();
    });

    test('defaults the requested cap to the server cap when the request omits it', async () => {
        const method = session(baseParams({ cap: 2_500_000n }));
        // No `cap` on the request → `request.cap ?? cap.toString()` uses the
        // server cap.
        const result = await method.request!({
            credential: null,
            request: { currency: 'USDC', operator: '', recipient: '' } as never,
        });
        expect(result.cap).toBe('2500000');
    });
});
