import { Store } from 'mppx';
import { describe, expect, it } from 'vitest';

import { configure } from '../config.js';
import { ConfigurationError } from '../errors.js';
import { Signer } from '../signer.js';

// An x402-only accept list must fail closed on the replay store exactly like the
// mpp path: off localnet the default in-memory store is process-local, so a
// second replica or a restart would accept a replayed payment. See SECURITY.md.
const X402 = { accept: ['x402'] as const, mpp: { challengeBindingSecret: 'test-secret' } };

describe('configure replay store for x402-only accept lists', () => {
    it('fails closed off localnet when no replay store is provided', async () => {
        const signer = await Signer.generate();
        await expect(configure({ ...X402, network: 'solana_mainnet', operator: { signer } })).rejects.toThrow(
            ConfigurationError,
        );
    });

    it('succeeds off localnet when a shared replay store is injected', async () => {
        const signer = await Signer.generate();
        const config = await configure({
            ...X402,
            network: 'solana_mainnet',
            operator: { signer },
            replayStore: Store.memory(),
        });
        expect(config.replayStore).toBeDefined();
    });

    it('succeeds on localnet without a replay store', async () => {
        const config = await configure({ ...X402, network: 'solana_localnet' });
        expect(config.replayStore).toBeDefined();
    });
});
