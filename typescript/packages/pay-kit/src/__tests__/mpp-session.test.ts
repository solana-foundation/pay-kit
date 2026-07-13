import { createMemorySessionStore } from '@solana/mpp/server';
import { Store } from 'mppx';
import { describe, expect, it, vi } from 'vitest';

import { createSessionEngine } from '../adapters/mpp-session.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import { session } from '../pricing.js';
import { Signer } from '../signer.js';

async function setup(
    options: {
        readonly network?: 'solana_devnet' | 'solana_localnet';
        readonly sessionStore?: ReturnType<typeof createMemorySessionStore>;
    } = {},
) {
    const signer = await Signer.generate();
    const config = await configure({
        mpp: {
            challengeBindingSecret: 's'.repeat(32),
            ...(options.sessionStore ? { sessionStore: options.sessionStore } : {}),
        },
        network: options.network ?? 'solana_localnet',
        operator: { signer },
        replayStore: Store.memory(),
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

    it('uses the injected store outside localnet', async () => {
        const store = createMemorySessionStore();
        const getChannel = vi.spyOn(store, 'getChannel');
        const { config, gate } = await setup({ network: 'solana_devnet', sessionStore: store });

        const engine = createSessionEngine(config, gate);
        await expect(engine.receipt('missing')).resolves.toBeUndefined();
        expect(getChannel).toHaveBeenCalledWith('missing');
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
});
