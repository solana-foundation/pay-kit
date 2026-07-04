import { Store } from 'mppx';
import { describe, expect, it } from 'vitest';

import { configure, configureFromEnv } from '../config.js';
import { ConfigurationError, DemoSignerOnMainnetError, ProtocolNotSupportedError } from '../errors.js';
import { Signer } from '../signer.js';

const SECRET = { mpp: { challengeBindingSecret: 'test-secret' } };
// Off-localnet configs additionally require a shared replay store; a fresh
// in-memory one satisfies the requirement for these unit tests.
const OFFNET = { ...SECRET, replayStore: Store.memory() };

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
        expect(config.x402.facilitatorFee).toBe(0);
    });

    it('refuses the demo signer on mainnet', async () => {
        await expect(configure({ ...SECRET, network: 'solana_mainnet' })).rejects.toThrow(DemoSignerOnMainnetError);
        const signer = await Signer.generate();
        const config = await configure({ ...OFFNET, network: 'solana_mainnet', operator: { signer } });
        expect(config.operator.recipient).toBe(signer.pubkey);
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

    it('validates the x402 facilitator fee', async () => {
        const config = await configure({ ...SECRET, x402: { facilitatorFee: 250 } });
        expect(config.x402.facilitatorFee).toBe(250);

        await expect(configure({ ...SECRET, x402: { facilitatorFee: -1 } })).rejects.toThrow(ConfigurationError);
        await expect(configure({ ...SECRET, x402: { facilitatorFee: 10_001 } })).rejects.toThrow(ConfigurationError);
        await expect(configure({ ...SECRET, x402: { facilitatorFee: 1.5 } })).rejects.toThrow(ConfigurationError);
    });

    it('requires a challenge secret outside localnet', async () => {
        const signer = await Signer.generate();
        delete process.env.PAY_KIT_MPP_SECRET;
        delete process.env.MPP_SECRET_KEY;
        await expect(configure({ network: 'solana_devnet', operator: { signer } })).rejects.toThrow(ConfigurationError);
        process.env.MPP_SECRET_KEY = 'env-secret';
        const config = await configure({ network: 'solana_devnet', operator: { signer }, replayStore: Store.memory() });
        expect(config.mpp.challengeBindingSecret).toBe('env-secret');
        delete process.env.MPP_SECRET_KEY;
    });

    it('requires a shared replay store outside localnet', async () => {
        const signer = await Signer.generate();
        // Off localnet the default in-memory replay store is process-local and
        // unsafe, so configure() must refuse it unless one is provided or the
        // single-process opt-out is set.
        await expect(configure({ ...SECRET, network: 'solana_devnet', operator: { signer } })).rejects.toThrow(
            ConfigurationError,
        );

        const provided = await configure({
            ...SECRET,
            network: 'solana_devnet',
            operator: { signer },
            replayStore: Store.memory(),
        });
        expect(provided.replayStore).toBeDefined();

        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const optedIn = await configure({ ...SECRET, network: 'solana_devnet', operator: { signer } });
            expect(optedIn.replayStore).toBeDefined();
        } finally {
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });

    it('configures from prefixed environment variables', async () => {
        process.env.PAY_KIT_NETWORK = 'solana_devnet';
        process.env.PAY_KIT_MPP_SECRET = 'env-secret';
        process.env.PAY_KIT_MPP_EXPIRES_IN = '60';
        process.env.PAY_KIT_STABLECOINS = '';
        process.env.PAY_KIT_RPC_URL = 'http://rpc.example';
        process.env.PAY_KIT_X402_FACILITATOR_FEE = '125';
        // configureFromEnv cannot pass a Store object, so opt into single-process
        // replay scope for this devnet env config.
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        try {
            const config = await configureFromEnv();
            expect(config.network).toBe('solana_devnet');
            expect(config.mpp.challengeBindingSecret).toBe('env-secret');
            expect(config.mpp.expiresIn).toBe(60);
            expect(config.rpcUrl).toBe('http://rpc.example');
            expect(config.x402.facilitatorFee).toBe(125);
        } finally {
            delete process.env.PAY_KIT_NETWORK;
            delete process.env.PAY_KIT_MPP_SECRET;
            delete process.env.PAY_KIT_MPP_EXPIRES_IN;
            delete process.env.PAY_KIT_STABLECOINS;
            delete process.env.PAY_KIT_RPC_URL;
            delete process.env.PAY_KIT_X402_FACILITATOR_FEE;
            delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        }
    });
});
