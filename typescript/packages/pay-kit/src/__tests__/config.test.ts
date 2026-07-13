import { describe, expect, it } from 'vitest';

import { configure, configureFromEnv } from '../config.js';
import { ConfigurationError, DemoSignerOnMainnetError, ProtocolNotSupportedError } from '../errors.js';
import { Signer } from '../signer.js';

const SECRET = { mpp: { challengeBindingSecret: 's'.repeat(32) } };

function createSharedReplayStore() {
    const entries = new Map<string, unknown>();
    return {
        delete: async (key: string) => {
            entries.delete(key);
        },
        get: async (key: string) => entries.get(key) ?? null,
        isDurable: true as const,
        isShared: true as const,
        put: async (key: string, value: unknown) => {
            entries.set(key, value);
        },
        reserve: async (key: string, value: unknown = true) => {
            if (entries.has(key)) return false;
            entries.set(key, value);
            return true;
        },
    };
}

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
        await expect(configure({ ...SECRET, network: 'solana_mainnet' })).rejects.toThrow(DemoSignerOnMainnetError);
        const signer = await Signer.generate();
        const config = await configure({
            ...SECRET,
            network: 'solana_mainnet',
            operator: { signer },
            replayStore: createSharedReplayStore(),
        });
        expect(config.operator.recipient).toBe(signer.pubkey);
    });

    it('refuses a demo key wrapped with a forged isDemo marker on mainnet', async () => {
        const demo = await Signer.demo();
        const signer = { ...demo, isDemo: false };

        await expect(
            configure({
                ...SECRET,
                network: 'solana_mainnet',
                operator: { signer },
                replayStore: createSharedReplayStore(),
            }),
        ).rejects.toThrow(DemoSignerOnMainnetError);
    });

    it('accepts the shipped protocols (mpp + x402)', async () => {
        const config = await configure({ ...SECRET, accept: ['x402', 'mpp'] });
        expect(config.accept).toEqual(['x402', 'mpp']);
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

    it('requires a challenge secret outside localnet', async () => {
        const signer = await Signer.generate();
        delete process.env.PAY_KIT_MPP_SECRET;
        delete process.env.MPP_SECRET_KEY;
        await expect(configure({ network: 'solana_devnet', operator: { signer } })).rejects.toThrow(ConfigurationError);
        process.env.MPP_SECRET_KEY = 'e'.repeat(32);
        try {
            const config = await configure({
                network: 'solana_devnet',
                operator: { signer },
                replayStore: createSharedReplayStore(),
            });
            expect(config.mpp.challengeBindingSecret).toBe('e'.repeat(32));
        } finally {
            delete process.env.MPP_SECRET_KEY;
        }
    });

    it('requires a 32-byte UTF-8 challenge secret outside localnet', async () => {
        const signer = await Signer.generate();
        await expect(
            configure({
                mpp: { challengeBindingSecret: 's'.repeat(31) },
                network: 'solana_devnet',
                operator: { signer },
                replayStore: createSharedReplayStore(),
            }),
        ).rejects.toThrow('mpp.challengeBindingSecret must be at least 32 UTF-8 bytes outside localnet.');

        await expect(
            configure({
                mpp: { challengeBindingSecret: '\ud83d\ude00'.repeat(8) },
                network: 'solana_devnet',
                operator: { signer },
                replayStore: createSharedReplayStore(),
            }),
        ).resolves.toMatchObject({ network: 'solana_devnet' });

        await expect(configure({ mpp: { challengeBindingSecret: 'short' } })).resolves.toMatchObject({
            network: 'solana_localnet',
        });
    });

    it('rejects missing, non-atomic, or unsafe MPP replay stores outside localnet', async () => {
        const signer = await Signer.generate();
        const options = { ...SECRET, network: 'solana_devnet' as const, operator: { signer } };
        await expect(configure(options)).rejects.toThrow('no shared replay store configured outside localnet');
        await expect(configure({ ...options, replayStore: null as never })).rejects.toThrow(
            'replayStore outside localnet must provide an atomic reserve() operation.',
        );
        await expect(
            configure({
                ...options,
                replayStore: {
                    delete: async () => undefined,
                    get: async () => null,
                    isDurable: true,
                    isShared: true,
                    put: async () => undefined,
                },
            }),
        ).rejects.toThrow('replayStore outside localnet must provide an atomic reserve() operation.');
        await expect(
            configure({ ...options, replayStore: { ...createSharedReplayStore(), isShared: false } }),
        ).rejects.toThrow('replayStore outside localnet must set isShared=true and isDurable=true.');
        await expect(
            configure({ ...options, replayStore: { ...createSharedReplayStore(), isDurable: false } }),
        ).rejects.toThrow('replayStore outside localnet must set isShared=true and isDurable=true.');
        await expect(configure({ ...options, replayStore: createSharedReplayStore() })).resolves.toMatchObject({
            network: 'solana_devnet',
        });

        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            await expect(configure(options)).resolves.toMatchObject({ network: 'solana_devnet' });
            await expect(configure({ ...options, network: 'solana_mainnet' })).rejects.toThrow(
                'no shared replay store configured outside localnet',
            );
            await expect(configure({ ...options, replayStore: null as never })).rejects.toThrow(
                'replayStore outside localnet must provide an atomic reserve() operation.',
            );
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('requires a shared durable replay store for x402-only servers outside localnet', async () => {
        const signer = await Signer.generate();
        // x402 settles an on-chain transaction and fences the signature against
        // replay exactly like MPP, so an x402-only server must not boot off
        // localnet without a shared durable replay store.
        const options = {
            accept: ['x402'] as const,
            network: 'solana_devnet' as const,
            operator: { signer },
        };
        await expect(configure(options)).rejects.toThrow('no shared replay store configured outside localnet');
        await expect(
            configure({ ...options, replayStore: { ...createSharedReplayStore(), isDurable: false } }),
        ).rejects.toThrow('replayStore outside localnet must set isShared=true and isDurable=true.');
        await expect(configure({ ...options, replayStore: createSharedReplayStore() })).resolves.toMatchObject({
            network: 'solana_devnet',
        });
        // localnet stays permissive for x402 too.
        await expect(configure({ ...options, network: 'solana_localnet' })).resolves.toMatchObject({
            network: 'solana_localnet',
        });
    });

    it('materializes a shared in-memory replay store on devnet under the opt-in', async () => {
        const signer = await Signer.generate();
        const options = { ...SECRET, network: 'solana_devnet' as const, operator: { signer } };

        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configure(options);
            const store = config.replayStore as { isDurable?: boolean; reserve?: unknown } | undefined;
            expect(store).toBeDefined();
            expect(typeof store?.reserve).toBe('function');
            // Not durable: the subscription adapter must still reject it downstream.
            expect(store?.isDurable).toBe(false);
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }

        // Without the opt-in nothing is materialized; configure fails closed.
        await expect(configure(options)).rejects.toThrow('no shared replay store configured outside localnet');
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

    it('configures from prefixed environment variables', async () => {
        process.env.PAY_KIT_NETWORK = 'solana_devnet';
        process.env.PAY_KIT_MPP_SECRET = 'e'.repeat(32);
        process.env.PAY_KIT_MPP_EXPIRES_IN = '60';
        process.env.PAY_KIT_STABLECOINS = '';
        process.env.PAY_KIT_RPC_URL = 'http://rpc.example';
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configureFromEnv('PAY_KIT_');
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
});
