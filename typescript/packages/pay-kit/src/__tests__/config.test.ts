import type { Store } from 'mppx';
import { describe, expect, it } from 'vitest';

import { configure, configureFromEnv } from '../config.js';
import { ConfigurationError, DemoSignerOnMainnetError, ProtocolNotSupportedError } from '../errors.js';
import { createUnsafeMemoryReplayStore, declareProductionReplayStore, type ReplayStore } from '../replay-store.js';
import { Signer } from '../signer.js';

// Off localnet the challenge secret must be at least 32 UTF-8 bytes, so every
// non-localnet fixture uses a 32-byte secret.
const SECRET_32 = 's'.repeat(32);
const SECRET = { mpp: { challengeBindingSecret: SECRET_32, allowUnsafeMemoryStore: true } };
const values = new Map<string, unknown>();
const SHARED_STORE: ReplayStore = declareProductionReplayStore({
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
const UNKNOWN_ATOMIC_STORE: ReplayStore = {
    async delete() {},
    async get() {
        return null;
    },
    async put() {},
    async putIfAbsent() {
        return true;
    },
};
const LEGACY_STORE: Store.Store = {
    async delete() {},
    async get() {
        return null;
    },
    async put() {},
};

describe('configure', () => {
    it('applies the canonical defaults', async () => {
        const config = await configure(SECRET);
        expect(config.network).toBe('solana_localnet');
        expect(config.accept).toEqual(['mpp']);
        expect(config.stablecoins).toEqual(['USDC']);
        expect(config.mpp.expiresIn).toBe(120);
        expect(config.mpp.realm).toBe('App');
        expect(config.operator.feePayer).toBe(true);
        expect(config.operator.signer.isDemo).toBe(true);
        expect(config.operator.recipient).toBe(config.operator.signer.pubkey);
        expect(config.rpcUrl).toBe('http://localhost:8899');
        expect(config.x402).toEqual({});
    });

    it('refuses the demo signer on mainnet', async () => {
        const mainnetMpp = { mpp: { challengeBindingSecret: SECRET_32 }, replayStore: SHARED_STORE };
        await expect(configure({ ...mainnetMpp, network: 'solana_mainnet' })).rejects.toThrow(DemoSignerOnMainnetError);
        const signer = await Signer.generate();
        const config = await configure({
            ...mainnetMpp,
            network: 'solana_mainnet',
            operator: { signer },
        });
        expect(config.operator.recipient).toBe(signer.pubkey);
    });

    it('refuses a demo key wrapped with a forged isDemo marker on mainnet', async () => {
        const demo = await Signer.demo();
        const signer = { ...demo, isDemo: false };

        await expect(
            configure({
                mpp: { challengeBindingSecret: SECRET_32 },
                network: 'solana_mainnet',
                operator: { signer },
                replayStore: SHARED_STORE,
            }),
        ).rejects.toThrow(DemoSignerOnMainnetError);
    });

    it('rejects the unsafe replay-store override on mainnet', async () => {
        const signer = await Signer.generate();
        await expect(configure({ ...SECRET, network: 'solana_mainnet', operator: { signer } })).rejects.toThrow(
            /forbidden on mainnet/,
        );
    });

    it('accepts the shipped protocols (mpp + x402)', async () => {
        const config = await configure({ ...SECRET, accept: ['x402', 'mpp'] });
        expect(config.accept).toEqual(['x402', 'mpp']);
    });

    it('does not require or construct an MPP replay store for x402-only config', async () => {
        // Store.Store remains accepted by the public input type for x402 compatibility.
        const config = await configure({ accept: ['x402'], replayStore: LEGACY_STORE });
        expect(config.accept).toEqual(['x402']);
        expect(config.replayStore).toBe(LEGACY_STORE);
    });

    it('does not reject the MPP-only unsafe-memory flag for x402-only mainnet config', async () => {
        const config = await configure({
            accept: ['x402'],
            mpp: { allowUnsafeMemoryStore: true },
            network: 'solana_mainnet',
            operator: { signer: await Signer.generate() },
        });
        expect(config.mpp.allowUnsafeMemoryStore).toBe(true);
    });

    it('fails closed at runtime for a legacy non-atomic MPP store', async () => {
        await expect(configure({ ...SECRET, replayStore: LEGACY_STORE as ReplayStore })).rejects.toThrow(
            /atomic putIfAbsent/,
        );
    });

    it.each([
        ['isShared-only', { ...SHARED_STORE, isDurable: false }],
        ['isDurable-only', { ...SHARED_STORE, isShared: false }],
        ['unknown capabilities', UNKNOWN_ATOMIC_STORE],
    ] satisfies readonly [string, ReplayStore][])(
        'rejects an undeclared atomic store with %s',
        async (_label, replayStore) => {
            const signer = await Signer.generate();
            await expect(
                configure({
                    ...SECRET,
                    mpp: { challengeBindingSecret: SECRET_32 },
                    network: 'solana_devnet',
                    operator: { signer },
                    replayStore,
                }),
            ).rejects.toThrow(/declareProductionReplayStore/);
        },
    );

    it('requires external production stores to affirm capabilities before declaration', () => {
        expect(() => declareProductionReplayStore(UNKNOWN_ATOMIC_STORE)).toThrow(/isShared=true and isDurable=true/);
    });

    it('rejects a spread-cloned memory store even when it claims production capabilities', async () => {
        const replayStore = {
            ...createUnsafeMemoryReplayStore(),
            isDurable: true,
            isShared: true,
        };

        expect(() => declareProductionReplayStore(createUnsafeMemoryReplayStore())).toThrow(/Process-local memory/);
        await expect(
            configure({
                ...SECRET,
                mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: SECRET_32 },
                network: 'solana_devnet',
                operator: { signer: await Signer.generate() },
                replayStore,
            }),
        ).rejects.toThrow(/declareProductionReplayStore/);
    });

    it('derives MPP sponsorship from a raw non-fee-payer signer', async () => {
        const signer = (await Signer.generate()).signer;
        const config = await configure({
            mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 'test-secret' },
            operator: { feePayer: false, signer },
        });
        expect(config.operator.feePayer).toBe(false);
        expect(config.operator.signer.isFeePayer).toBe(false);
    });

    it('rejects a prewrapped signer configured to sponsor when it cannot', async () => {
        const signer = Signer.from((await Signer.generate()).signer, { feePayer: false });
        await expect(
            configure({
                mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 'test-secret' },
                operator: { feePayer: true, signer },
            }),
        ).rejects.toThrow(/permits fee sponsorship/);
    });

    it('rejects an x402 configuration without a sponsoring operator', async () => {
        const signer = Signer.from((await Signer.generate()).signer, { feePayer: false });
        await expect(configure({ accept: ['x402'], operator: { signer } })).rejects.toThrow(
            /x402 requires an operator fee payer/,
        );
    });

    it('rejects protocols this SDK does not ship', async () => {
        await expect(configure({ ...SECRET, accept: ['stripe' as never] })).rejects.toThrow(ProtocolNotSupportedError);
        await expect(configure({ ...SECRET, accept: [] })).rejects.toThrow(ConfigurationError);
    });

    it('validates stablecoins and expiry', async () => {
        await expect(configure({ ...SECRET, stablecoins: ['DOGE' as never] })).rejects.toThrow(ConfigurationError);
        await expect(configure({ ...SECRET, mpp: { ...SECRET.mpp, expiresIn: -1 } })).rejects.toThrow(
            ConfigurationError,
        );
    });

    it('rejects expirations that overflow Date while preserving expiresIn=0', async () => {
        await expect(
            configure({ ...SECRET, mpp: { ...SECRET.mpp, expiresIn: Number.MAX_SAFE_INTEGER } }),
        ).rejects.toThrow('mpp.expiresIn must produce a valid expiration date.');

        await expect(configure({ ...SECRET, mpp: { ...SECRET.mpp, expiresIn: 0 } })).resolves.toMatchObject({
            mpp: { expiresIn: 0 },
        });
    });

    it('rejects malformed explicit MPP challenge secrets before expiry validation on localnet', async () => {
        await expect(configure({ mpp: { challengeBindingSecret: '' } })).rejects.toThrow(
            'mpp.challengeBindingSecret must be a non-empty string.',
        );
        await expect(configure({ mpp: { challengeBindingSecret: null as never, expiresIn: -1 } })).rejects.toThrow(
            'mpp.challengeBindingSecret must be a non-empty string.',
        );
        await expect(configure({ mpp: { challengeBindingSecret: 1 as never, expiresIn: -1 } })).rejects.toThrow(
            'mpp.challengeBindingSecret must be a non-empty string.',
        );
    });

    it('requires a challenge secret outside localnet', async () => {
        const signer = await Signer.generate();
        delete process.env.PAY_KIT_MPP_SECRET;
        delete process.env.MPP_SECRET_KEY;
        await expect(configure({ network: 'solana_devnet', operator: { signer } })).rejects.toThrow(ConfigurationError);
        process.env.MPP_SECRET_KEY = 'e'.repeat(32);
        const config = await configure({ network: 'solana_devnet', operator: { signer }, replayStore: SHARED_STORE });
        expect(config.mpp.challengeBindingSecret).toBe('e'.repeat(32));
        delete process.env.MPP_SECRET_KEY;
    });

    it('requires a 32-byte UTF-8 challenge secret outside localnet', async () => {
        const signer = await Signer.generate();
        await expect(
            configure({
                mpp: { challengeBindingSecret: 's'.repeat(31) },
                network: 'solana_devnet',
                operator: { signer },
                replayStore: SHARED_STORE,
            }),
        ).rejects.toThrow('mpp.challengeBindingSecret must be at least 32 UTF-8 bytes outside localnet.');

        // 8 grinning-face emoji encode to 32 UTF-8 bytes, so the byte count (not
        // the string length) is what the boundary measures.
        await expect(
            configure({
                mpp: { challengeBindingSecret: '😀'.repeat(8) },
                network: 'solana_devnet',
                operator: { signer },
                replayStore: SHARED_STORE,
            }),
        ).resolves.toMatchObject({ network: 'solana_devnet' });

        // A short secret is still accepted on localnet.
        await expect(
            configure({ mpp: { allowUnsafeMemoryStore: true, challengeBindingSecret: 'short' } }),
        ).resolves.toMatchObject({ network: 'solana_localnet' });
    });

    it('requires an injected replay store outside localnet and accepts both capabilities', async () => {
        const signer = await Signer.generate();
        await expect(
            configure({
                ...SECRET,
                mpp: { challengeBindingSecret: SECRET_32 },
                network: 'solana_devnet',
                operator: { signer },
            }),
        ).rejects.toThrow(/atomic shared replayStore/);

        await expect(configure({ mpp: { challengeBindingSecret: 'test-secret' } })).rejects.toThrow(
            /atomic shared replayStore/,
        );

        const local = await configure(SECRET);
        expect(local.replayStore).toBeDefined();

        const production = await configure({
            ...SECRET,
            network: 'solana_devnet',
            operator: { signer },
            replayStore: SHARED_STORE,
        });
        expect(production.replayStore).toBe(SHARED_STORE);
    });

    it('honors the explicit in-memory replay-store environment opt-in', async () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configure({
                mpp: { challengeBindingSecret: SECRET_32 },
                network: 'solana_devnet',
                operator: { signer: await Signer.generate() },
            });
            expect(config.mpp.allowUnsafeMemoryStore).toBe(true);
            expect(config.replayStore).toBeDefined();
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('configures from prefixed environment variables', async () => {
        process.env.PAY_KIT_NETWORK = 'solana_devnet';
        process.env.PAY_KIT_MPP_SECRET = 'e'.repeat(32);
        process.env.PAY_KIT_MPP_EXPIRES_IN = '60';
        process.env.PAY_KIT_STABLECOINS = '';
        process.env.PAY_KIT_RPC_URL = 'http://rpc.example';
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configureFromEnv('PAY_KIT_', SHARED_STORE);
            expect(config.network).toBe('solana_devnet');
            expect(config.mpp.challengeBindingSecret).toBe('e'.repeat(32));
            expect(config.mpp.expiresIn).toBe(60);
            expect(config.rpcUrl).toBe('http://rpc.example');
            expect(config.x402).toEqual({});
        } finally {
            delete process.env.PAY_KIT_NETWORK;
            delete process.env.PAY_KIT_MPP_SECRET;
            delete process.env.PAY_KIT_MPP_EXPIRES_IN;
            delete process.env.PAY_KIT_STABLECOINS;
            delete process.env.PAY_KIT_RPC_URL;
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('honors a custom-prefixed unsafe-memory environment opt-in', async () => {
        process.env.APP_NETWORK = 'solana_devnet';
        process.env.APP_MPP_SECRET = 'a'.repeat(32);
        process.env.APP_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configureFromEnv('APP_');
            expect(config.mpp.allowUnsafeMemoryStore).toBe(true);
            expect(config.replayStore).toBeDefined();
        } finally {
            delete process.env.APP_NETWORK;
            delete process.env.APP_MPP_SECRET;
            delete process.env.APP_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('does not inherit the default prefix unsafe-memory opt-in', async () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        process.env.APP_NETWORK = 'solana_devnet';
        process.env.APP_MPP_SECRET = 'a'.repeat(32);
        try {
            await expect(configureFromEnv('APP_')).rejects.toThrow(/atomic shared replayStore/);
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
            delete process.env.APP_NETWORK;
            delete process.env.APP_MPP_SECRET;
        }
    });
});
