import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ConfigurationError } from '../errors.js';

// --- Boundary mocks -------------------------------------------------------
// The session engine wires @solana/mpp's session() method, its side-channel
// session.routes(), an in-memory store, and an Mppx handler — all of which
// need a live RPC/crypto to actually open a channel. They are stubbed so the
// engine's construction guards, handler/side-channel delegation, and the
// receipt reader (found + unknown-channel branches) run offline.
// resolveStablecoinMint stays real (offline-safe).

type ChannelState = {
    channelId: string;
    cumulative: bigint;
    deposit: bigint;
    finalized: boolean;
    settledSignature?: string | null;
};

const storeControl: { channel: ChannelState | undefined } = { channel: undefined };

const routeControl: {
    commit: (r: Request) => Promise<Response>;
    deliveries: (r: Request) => Promise<Response>;
} = {
    commit: () => Promise.resolve(new Response('committed')),
    deliveries: () => Promise.resolve(new Response('reserved')),
};

const handlerControl: { impl: (r: Request) => Promise<unknown> } = {
    impl: () => Promise.resolve({ status: 200, withReceipt: (r: Response) => r }),
};

let lastSessionParams: Record<string, unknown> | undefined;
let lastHandlerOptions: Record<string, unknown> | undefined;

vi.mock('@solana/mpp/server', () => {
    const sessionFn = Object.assign(
        (params: Record<string, unknown>) => {
            lastSessionParams = params;
            return { kind: 'session-method' };
        },
        {
            routes: () => ({
                commit: (r: Request) => routeControl.commit(r),
                deliveries: (r: Request) => routeControl.deliveries(r),
            }),
        },
    );
    class FakeMppx {
        static create(): FakeMppx {
            return new FakeMppx();
        }
        session(options: Record<string, unknown>) {
            lastHandlerOptions = options;
            return (request: Request) => handlerControl.impl(request);
        }
    }
    return {
        createMemorySessionStore: () => ({
            getChannel: () => Promise.resolve(storeControl.channel),
        }),
        Mppx: FakeMppx,
        session: sessionFn,
    };
});

vi.mock('@solana/kit', async () => {
    const actual = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
    return { ...actual, createSolanaRpc: () => ({ __rpc: true }) };
});

const { createSessionEngine } = await import('../adapters/mpp-session.js');
const { configure } = await import('../config.js');
const { Gate } = await import('../gate.js');
const { session } = await import('../pricing.js');
const { usd } = await import('../price.js');
const { gateDefaults } = await import('../pricing.js');

const SELLER = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj';

async function sessionGate(overrides: Parameters<typeof session>[1] = { unitPrice: usd('0.0001') }) {
    const config = await configure({
        mpp: { challengeBindingSecret: 'session-secret' },
        operator: { recipient: SELLER },
    });
    const gate = Gate.create({ ...session(usd('1.00'), { ...overrides }), name: 'stream' }, gateDefaults(config));
    return { config, gate };
}

describe('createSessionEngine', () => {
    beforeEach(() => {
        lastSessionParams = undefined;
        lastHandlerOptions = undefined;
        storeControl.channel = undefined;
        routeControl.commit = () => Promise.resolve(new Response('committed'));
        routeControl.deliveries = () => Promise.resolve(new Response('reserved'));
        handlerControl.impl = () => Promise.resolve({ status: 200, withReceipt: (r: Response) => r });
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    it('rejects a gate without a session config', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'session-secret' },
            operator: { recipient: SELLER },
        });
        const fixed = Gate.create({ amount: usd('1.00'), name: 'stream' }, gateDefaults(config));
        expect(() => createSessionEngine(config, fixed)).toThrow(ConfigurationError);
        expect(() => createSessionEngine(config, fixed)).toThrow(/requires a session config/);
    });

    it('rejects an operator that does not sponsor fees', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'session-secret' },
            operator: { feePayer: false, recipient: SELLER },
        });
        const gate = Gate.create(
            { ...session(usd('1.00'), { unitPrice: usd('0.0001') }), name: 'stream' },
            gateDefaults(config),
        );
        expect(() => createSessionEngine(config, gate)).toThrow(/operator that sponsors fees/);
    });

    it('builds an engine exposing all four surfaces', async () => {
        const { config, gate } = await sessionGate();
        const engine = createSessionEngine(config, gate);
        expect(typeof engine.commit).toBe('function');
        expect(typeof engine.deliveries).toBe('function');
        expect(typeof engine.handler).toBe('function');
        expect(typeof engine.receipt).toBe('function');
    });

    it('passes the cap and per-delivery price into the session params', async () => {
        const { config, gate } = await sessionGate();
        createSessionEngine(config, gate);
        expect(lastSessionParams?.cap).toBe(1_000_000n);
        expect(lastSessionParams?.pricing).toEqual({ perDelivery: 100n });
        expect(lastSessionParams?.recipient).toBe(SELLER);
    });

    it('forwards the close-delay when configured', async () => {
        const { config, gate } = await sessionGate({ closeDelayMs: 5_000, unitPrice: usd('0.0001') });
        createSessionEngine(config, gate);
        expect(lastSessionParams?.closeDelayMs).toBe(5_000);
    });

    it('defaults the handler description when the gate omits one', async () => {
        const { config, gate } = await sessionGate();
        createSessionEngine(config, gate);
        expect(lastHandlerOptions?.description).toBe('Metered session');
    });

    it('uses the gate description for the handler when present', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'session-secret' },
            operator: { recipient: SELLER },
        });
        const gate = Gate.create(
            { ...session(usd('1.00'), { description: 'Live feed', unitPrice: usd('0.0001') }), name: 'stream' },
            gateDefaults(config),
        );
        createSessionEngine(config, gate);
        expect(lastHandlerOptions?.description).toBe('Live feed');
    });

    it('delegates commit and deliveries to the side-channel routes', async () => {
        const { config, gate } = await sessionGate();
        const engine = createSessionEngine(config, gate);
        expect(await (await engine.commit(new Request('http://t/commit'))).text()).toBe('committed');
        expect(await (await engine.deliveries(new Request('http://t/deliveries'))).text()).toBe('reserved');
    });

    it('delegates the gated route to the Mppx session handler', async () => {
        handlerControl.impl = () => Promise.resolve({ challenge: new Response('402'), status: 402 });
        const { config, gate } = await sessionGate();
        const engine = createSessionEngine(config, gate);
        const result = await engine.handler(new Request('http://t/stream'));
        expect(result.status).toBe(402);
    });

    it('returns a receipt snapshot for a known channel', async () => {
        storeControl.channel = {
            channelId: 'chan-9',
            cumulative: 42n,
            deposit: 1_000_000n,
            finalized: true,
            settledSignature: 'SettledSig',
        };
        const { config, gate } = await sessionGate();
        const engine = createSessionEngine(config, gate);
        const receipt = await engine.receipt('chan-9');
        expect(receipt).toEqual({
            channelId: 'chan-9',
            cumulative: '42',
            deposit: '1000000',
            finalized: true,
            settledSignature: 'SettledSig',
        });
    });

    it('coerces a null settled signature', async () => {
        storeControl.channel = {
            channelId: 'chan-9',
            cumulative: 0n,
            deposit: 1_000_000n,
            finalized: false,
            settledSignature: null,
        };
        const { config, gate } = await sessionGate();
        const engine = createSessionEngine(config, gate);
        const receipt = await engine.receipt('chan-9');
        expect(receipt?.settledSignature).toBeNull();
    });

    it('treats a missing settledSignature as null', async () => {
        storeControl.channel = { channelId: 'chan-9', cumulative: 0n, deposit: 1n, finalized: false };
        const { config, gate } = await sessionGate();
        const engine = createSessionEngine(config, gate);
        const receipt = await engine.receipt('chan-9');
        expect(receipt?.settledSignature).toBeNull();
    });

    it('returns undefined for an unknown channel', async () => {
        storeControl.channel = undefined;
        const { config, gate } = await sessionGate();
        const engine = createSessionEngine(config, gate);
        expect(await engine.receipt('missing')).toBeUndefined();
    });
});
