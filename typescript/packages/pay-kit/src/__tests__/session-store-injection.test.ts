import { generateKeyPairSigner, getBase58Decoder, type KeyPairSigner } from '@solana/kit';
import { createMemorySessionStore, encodeVoucherMessageBytes, type ChannelState } from '@solana/mpp/server';
import { Challenge, Credential } from 'mppx';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createSessionEngine } from '../adapters/mpp-session.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import type { NodeResponse } from '../http.js';
import type { SessionStore } from '../index.js';
import { createPayKit, type SessionRouteRequest } from '../paykit.js';
import { usd } from '../price.js';
import { session } from '../pricing.js';

// Only RPC is replaced: the method, voucher verification, routes and lifecycle
// remain real. No request reaches a network or uses funded wallets.
const rpc = vi.hoisted(() => ({
    getAccountInfo: vi.fn(() => ({ send: async () => ({ value: null }) })),
    getLatestBlockhash: vi.fn(() => ({
        send: async () => ({
            context: { slot: 314n },
            value: { blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N', lastValidBlockHeight: 100n },
        }),
    })),
    getSignatureStatuses: vi.fn(() => ({
        send: async () => ({ value: [{ confirmationStatus: 'finalized', err: null, slot: 314n }] }),
    })),
    sendTransaction: vi.fn(() => ({ send: async () => 'OfflineSettlementSignature' })),
}));

vi.mock('@solana/kit', async importOriginal => ({
    ...(await importOriginal<typeof import('@solana/kit')>()),
    createSolanaRpc: () => rpc,
}));

vi.mock('@solana/mpp/server', async importOriginal => {
    const actual = await importOriginal<typeof import('@solana/mpp/server')>();
    return { ...actual, createMemorySessionStore: vi.fn(actual.createMemorySessionStore) };
});

const CHANNEL = '11111111111111111111111111111111';
const URL = 'http://merchant.test/stream';

function state(signer: string, overrides: Partial<ChannelState> = {}): ChannelState {
    return {
        authorizedSigner: signer,
        channelId: CHANNEL,
        committedDeliveries: [],
        cumulative: 0n,
        deposit: 1_000_000n,
        idleTimeoutSeconds: 300,
        lastActivityAt: Date.now(),
        nextDeliverySequence: 0n,
        payer: signer,
        pendingDeliveries: [],
        processedUses: [],
        rentPayer: signer,
        sealed: false,
        settledOnChain: 0n,
        spentAmount: 0n,
        ...overrides,
    };
}

async function voucher(signer: KeyPairSigner, cumulativeAmount: string) {
    const data = { channelId: CHANNEL, cumulativeAmount, expiresAt: Math.floor(Date.now() / 1_000) + 3_600 };
    const [signatures] = await signer.signMessages([
        {
            content: encodeVoucherMessageBytes({
                ...data,
                cumulativeAmount: BigInt(data.cumulativeAmount),
                expiresAt: BigInt(data.expiresAt),
            }),
            signatures: {},
        },
    ]);
    return {
        signature: getBase58Decoder().decode(new Uint8Array(signatures![signer.address]!)),
        signatureType: 'ed25519' as const,
        signer: signer.address,
        voucher: data,
    };
}

async function setup(store?: SessionStore) {
    const config = await configure({ mpp: { challengeBindingSecret: 'offline-session-store-test-secret-key' } });
    const definition = session(usd('1'), { store, unitPrice: usd('0.0001') });
    const gate = Gate.create({ ...definition, name: 'stream' }, { accept: ['mpp'], payTo: config.operator.recipient });
    return { config, definition, gate };
}

function nodeRequest(body?: unknown, authorization?: string): SessionRouteRequest {
    return {
        body,
        headers: { ...(authorization ? { authorization } : {}), host: 'merchant.test' },
        method: 'POST',
        params: { channelId: CHANNEL },
        url: '/__402/session/deliveries',
    } as unknown as SessionRouteRequest;
}

function nodeResponse() {
    let body = '';
    const response = {
        end: (chunk: string | Uint8Array) => {
            body = chunk.toString();
        },
        setHeader: vi.fn(),
        statusCode: 200,
        writeHead: (status: number) => {
            response.statusCode = status;
        },
    };
    return { json: () => JSON.parse(body), response: response as unknown as NodeResponse };
}

afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.clearAllMocks();
});

describe('session store injection', () => {
    it('keeps the exact caller store in the frozen gate without freezing its implementation', async () => {
        const store = createMemorySessionStore();
        const { definition, gate } = await setup(store);
        expect(definition.session.store).toBe(store);
        expect(gate.session?.store).toBe(store);
        expect(Object.isFrozen(gate.session)).toBe(true);
        expect(Object.isFrozen(store)).toBe(false);
    });

    it('shares supplied state across payment, voucher, delivery, commit and receipt paths', async () => {
        const store = createMemorySessionStore();
        const signer = await generateKeyPairSigner();
        const { config, definition } = await setup(store);
        vi.mocked(createMemorySessionStore).mockClear();
        const pay = await createPayKit({ adapters: [], config, pricing: { stream: definition } });
        const routes = pay.sessionRoutes('stream');
        const challengeResponse = await pay.requirePayment(new Request(URL), 'stream');
        expect(challengeResponse).toMatchObject({ status: 402 });
        if (!('challenge' in challengeResponse)) throw new Error('expected challenge');
        const challenge = Challenge.deserialize(challengeResponse.response.headers.get('www-authenticate')!);
        await store.updateChannel(CHANNEL, () => state(signer.address, { openingChallengeId: challenge.id }));
        const credential = async (amount: string) =>
            Credential.serialize(
                Credential.from({
                    challenge,
                    payload: { action: 'voucher', channelId: CHANNEL, voucher: await voucher(signer, amount) },
                }),
            );

        const paid = await pay.requirePayment(
            new Request(URL, { headers: { authorization: await credential('100') } }),
            'stream',
        );
        expect(paid).toMatchObject({ status: 200 });
        expect((await store.getChannel(CHANNEL))?.spentAmount).toBe(100n);
        const ack = nodeResponse();
        await routes.voucher(nodeRequest({}, await credential('200')), ack.response);
        expect(ack.response.statusCode).toBe(200);
        expect((await store.getChannel(CHANNEL))?.cumulative).toBe(200n);

        const delivery = nodeResponse();
        await routes.deliveries(
            nodeRequest({ amount: '100', deliveryId: 'd1', sessionId: CHANNEL }),
            delivery.response,
        );
        expect(delivery.response.statusCode).toBe(200);
        expect((await store.getChannel(CHANNEL))?.pendingDeliveries).toHaveLength(1);
        const commit = nodeResponse();
        await routes.commit(nodeRequest({ deliveryId: 'd1', voucher: await voucher(signer, '300') }), commit.response);
        expect(commit.response.statusCode).toBe(200);
        expect(commit.json()).toMatchObject({ cumulative: '300', status: 'committed' });
        expect((await store.getChannel(CHANNEL))?.committedDeliveries).toHaveLength(1);

        const receipt = nodeResponse();
        await pay.sessionRoutes('stream').receipt(nodeRequest(), receipt.response);
        expect(receipt.response.statusCode).toBe(200);
        expect(receipt.json()).toMatchObject({ channelId: CHANNEL, cumulative: '300', sealed: false });
        expect(createMemorySessionStore).not.toHaveBeenCalled();
    });

    it('restores and settles idle channels through the supplied store', async () => {
        vi.useFakeTimers();
        const store = createMemorySessionStore();
        const { config, gate } = await setup(store);
        await store.updateChannel(CHANNEL, () =>
            state(config.operator.recipient, {
                idleTimeoutSeconds: 1,
                lastActivityAt: Date.now(),
            }),
        );
        const list = vi.spyOn(store, 'listChannels');
        const engine = createSessionEngine(config, gate);
        await vi.advanceTimersByTimeAsync(1_001);
        expect(list).toHaveBeenCalledWith({ sealed: false });
        await vi.waitFor(async () => {
            expect(await engine.receipt(CHANNEL)).toMatchObject({
                sealed: true,
                settledSignature: 'OfflineSettlementSignature',
            });
        });
        expect(rpc.sendTransaction).toHaveBeenCalledTimes(1);
        expect((await store.getChannel(CHANNEL))?.closeRequestedAt).toBeDefined();
    });

    it('preserves one isolated memory default per engine, including explicit undefined', async () => {
        const { config, gate } = await setup();
        vi.mocked(createMemorySessionStore).mockClear();
        const first = createSessionEngine(config, gate);
        const second = createSessionEngine(config, gate);
        expect(createMemorySessionStore).toHaveBeenCalledTimes(2);
        const firstStore = vi.mocked(createMemorySessionStore).mock.results[0]!.value as SessionStore;
        await firstStore.updateChannel(CHANNEL, () => state(config.operator.recipient));
        expect(await first.receipt(CHANNEL)).toMatchObject({ cumulative: '0' });
        expect(await second.receipt(CHANNEL)).toBeUndefined();
    });

    it('reports supplied-store failures without falling back to memory', async () => {
        const store = createMemorySessionStore();
        const { config, gate } = await setup(store);
        vi.spyOn(store, 'getChannel').mockRejectedValue(new Error('store unavailable'));
        vi.spyOn(store, 'updateChannel').mockRejectedValue(new Error('store unavailable'));
        vi.mocked(createMemorySessionStore).mockClear();
        const engine = createSessionEngine(config, gate);
        await expect(engine.receipt(CHANNEL)).rejects.toThrow('store unavailable');
        const response = await engine.deliveries(
            new Request(URL, { method: 'POST', body: JSON.stringify({ amount: '1', sessionId: CHANNEL }) }),
        );
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({ error: 'store unavailable' });
        expect(createMemorySessionStore).not.toHaveBeenCalled();
    });

    it.each(['custom-to-custom', 'custom-to-default', 'default-to-custom'] as const)(
        'rejects a cached gate store change: %s',
        async transition => {
            const first = transition === 'default-to-custom' ? undefined : createMemorySessionStore();
            const second = transition === 'custom-to-default' ? undefined : createMemorySessionStore();
            const { config, gate } = await setup(first);
            const other = Gate.create(
                { ...session(usd('1'), { store: second, unitPrice: usd('0.0001') }), name: gate.name },
                { accept: ['mpp'], payTo: gate.payTo },
            );
            const pay = await createPayKit({ adapters: [], config, pricing: {} });
            pay.sessionRoutes(gate);
            expect(() => pay.sessionRoutes(other)).toThrow('session store differs');
        },
    );

    it('allows repeated access with the same store, but rejects sharing it between gate names', async () => {
        const store = createMemorySessionStore();
        const { config, definition } = await setup(store);
        const pay = await createPayKit({ adapters: [], config, pricing: { first: definition, second: definition } });
        expect(() => {
            pay.sessionRoutes('first');
            pay.sessionRoutes('first');
        }).not.toThrow();
        expect(() => pay.sessionRoutes('second')).toThrow('already used by gate "first"');
    });

    it('allows distinct gates with separate stores and keeps their receipts isolated', async () => {
        const first = createMemorySessionStore();
        const second = createMemorySessionStore();
        const { config, definition } = await setup(first);
        await first.updateChannel(CHANNEL, () => state(config.operator.recipient));
        const pay = await createPayKit({
            adapters: [],
            config,
            pricing: {
                first: definition,
                second: session(usd('1'), { store: second, unitPrice: usd('0.0001') }),
            },
        });
        const found = nodeResponse();
        await pay.sessionRoutes('first').receipt(nodeRequest(), found.response);
        expect(found.response.statusCode).toBe(200);
        const missing = nodeResponse();
        await pay.sessionRoutes('second').receipt(nodeRequest(), missing.response);
        expect(missing.response.statusCode).toBe(404);
        expect(missing.json()).toEqual({ error: 'channel-not-found' });
    });

    it('does not claim store ownership when engine initialization fails', async () => {
        const store = createMemorySessionStore();
        const { config, definition } = await setup(store);
        const pay = await createPayKit({
            adapters: [],
            config,
            pricing: {
                invalid: session(usd('1'), { store, unitPrice: usd('0') }),
                valid: definition,
            },
        });
        expect(() => pay.sessionRoutes('invalid')).toThrow('amount must be positive');
        expect(() => pay.sessionRoutes('valid')).not.toThrow();
    });
});
