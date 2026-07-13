import { describe, expect, it } from 'vitest';

import { configure, configureFromEnv } from '../config.js';
import { ConfigurationError, DemoSignerOnMainnetError, ProtocolNotSupportedError } from '../errors.js';
import { Signer } from '../signer.js';

const SECRET = { mpp: { challengeBindingSecret: 's'.repeat(32) } };

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
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configure({ ...SECRET, network: 'solana_mainnet', operator: { signer } });
            expect(config.operator.recipient).toBe(signer.pubkey);
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
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
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configure({ network: 'solana_devnet', operator: { signer } });
            expect(config.mpp.challengeBindingSecret).toBe('e'.repeat(32));
        } finally {
            delete process.env.MPP_SECRET_KEY;
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('requires a 32-byte UTF-8 challenge secret outside localnet', async () => {
        const signer = await Signer.generate();
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            await expect(
                configure({
                    mpp: { challengeBindingSecret: 's'.repeat(31) },
                    network: 'solana_devnet',
                    operator: { signer },
                }),
            ).rejects.toThrow('mpp.challengeBindingSecret must be at least 32 UTF-8 bytes outside localnet.');

            await expect(
                configure({
                    mpp: { challengeBindingSecret: '\ud83d\ude00'.repeat(8) },
                    network: 'solana_devnet',
                    operator: { signer },
                }),
            ).resolves.toMatchObject({ network: 'solana_devnet' });

            await expect(configure({ mpp: { challengeBindingSecret: 'short' } })).resolves.toMatchObject({
                network: 'solana_localnet',
            });
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('requires a shared MPP replay store outside localnet unless explicitly opted in', async () => {
        const signer = await Signer.generate();
        await expect(
            configure({
                ...SECRET,
                network: 'solana_devnet',
                operator: { signer },
            }),
        ).rejects.toThrow(/PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE/);

        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            await expect(
                configure({
                    ...SECRET,
                    network: 'solana_devnet',
                    operator: { signer },
                }),
            ).resolves.toMatchObject({ network: 'solana_devnet' });
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
            const config = await configureFromEnv();
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
