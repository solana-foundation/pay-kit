import { createMemorySessionStore, type SessionStore } from '@solana/mpp/server';
import { describe, expect, it, vi } from 'vitest';

import { createSessionEngine } from '../adapters/mpp-session.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import { createPayKit } from '../paykit.js';
import { usd } from '../price.js';
import { session } from '../pricing.js';
import { declareProductionReplayStore, type ReplayStore } from '../replay-store.js';
import { Signer } from '../signer.js';

// Satisfies the replay-store policy so configure() succeeds; the session-store
// assertions below exercise the session engine's own store policy.
function sharedReplayStore(): ReplayStore {
    const values = new Map<string, unknown>();
    return declareProductionReplayStore({
        isDurable: true,
        isShared: true,
        async delete(key) {
            values.delete(key);
        },
        async get(key) {
            return (values.get(key) ?? null) as never;
        },
        async put(key, value) {
            values.set(key, value);
        },
        async putIfAbsent(key, value) {
            if (values.has(key)) return false;
            values.set(key, value);
            return true;
        },
    });
}

/** A durable (non in-memory-branded) SessionStore, delegating to the in-memory impl. */
function createDurableSessionStore(): SessionStore {
    const inner = createMemorySessionStore();
    return {
        deleteChannel: channelId => inner.deleteChannel(channelId),
        getChannel: channelId => inner.getChannel(channelId),
        listChannels: filter => inner.listChannels(filter),
        markSealed: channelId => inner.markSealed(channelId),
        updateChannel: (channelId, mutator) => inner.updateChannel(channelId, mutator),
    };
}

async function setup(
    options: {
        readonly network?: 'solana_devnet' | 'solana_localnet' | 'solana_mainnet';
        readonly sessionStore?: SessionStore;
    } = {},
) {
    const signer = await Signer.generate();
    const config = await configure({
        mpp: {
            // A production replay store is always injected, so the charge-level
            // unsafe-memory flag stays off; this keeps the process-wide session
            // opt-in env from tripping the mainnet charge-policy guard, letting
            // these tests reach the session-store engine assertions.
            allowUnsafeMemoryStore: false,
            challengeBindingSecret: 's'.repeat(32),
            ...(options.sessionStore ? { sessionStore: options.sessionStore } : {}),
        },
        network: options.network ?? 'solana_localnet',
        operator: { signer },
        replayStore: sharedReplayStore(),
    });
    const gate = Gate.create(
        {
            ...session(usd('1.00'), { unitPrice: usd('0.0001') }),
            name: 'metered',
            payTo: signer.pubkey,
        },
        { accept: ['mpp'], payTo: signer.pubkey },
    );
    return { config, gate };
}

describe('createSessionEngine', () => {
    it('rejects a nonlocal session engine without an injected store', async () => {
        const { config, gate } = await setup({ network: 'solana_devnet' });

        expect(() => createSessionEngine(config, gate)).toThrow(/mpp\.sessionStore is required outside localnet/);
    });

    it('uses a durable injected store outside localnet without the opt-in', async () => {
        const store = createDurableSessionStore();
        const getChannel = vi.spyOn(store, 'getChannel');
        const { config, gate } = await setup({ network: 'solana_devnet', sessionStore: store });

        const engine = createSessionEngine(config, gate);
        await expect(engine.receipt('missing')).resolves.toBeUndefined();
        expect(getChannel).toHaveBeenCalledWith('missing');
    });

    it('uses an explicit in-memory store outside localnet only under the opt-in', async () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const store = createMemorySessionStore();
            const getChannel = vi.spyOn(store, 'getChannel');
            const { config, gate } = await setup({ network: 'solana_devnet', sessionStore: store });

            const engine = createSessionEngine(config, gate);
            await expect(engine.receipt('missing')).resolves.toBeUndefined();
            expect(getChannel).toHaveBeenCalledWith('missing');
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('rejects an explicit in-memory store on devnet without the opt-in', async () => {
        const { config, gate } = await setup({
            network: 'solana_devnet',
            sessionStore: createMemorySessionStore(),
        });

        expect(() => createSessionEngine(config, gate)).toThrow(/mpp\.sessionStore is required outside localnet/);
    });

    it('rejects an explicit in-memory store on mainnet even with the opt-in', async () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const { config, gate } = await setup({
                network: 'solana_mainnet',
                sessionStore: createMemorySessionStore(),
            });

            expect(() => createSessionEngine(config, gate)).toThrow(/mpp\.sessionStore is required outside localnet/);
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('retains the localnet and explicit-override in-memory fallbacks', async () => {
        const localnet = await setup();
        expect(() => createSessionEngine(localnet.config, localnet.gate)).not.toThrow();

        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const devnet = await setup({ network: 'solana_devnet' });
            expect(() => createSessionEngine(devnet.config, devnet.gate)).not.toThrow();
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('rejects a mainnet process-local store override through sessionRoutes', async () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const { config } = await setup({ network: 'solana_mainnet' });
            const paykit = await createPayKit({
                config,
                pricing: { metered: session(usd('1.00'), { unitPrice: usd('0.0001') }) },
            });

            expect(() => paykit.sessionRoutes('metered')).toThrow(
                'mpp.sessionStore is required outside localnet; provide a durable shared store or, on devnet only, set ' +
                    'PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 for an explicit in-memory override.',
            );
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });
});
