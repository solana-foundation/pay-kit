import { createMemorySessionStore } from '@solana/mpp/server';
import { Store } from 'mppx';
import { describe, expect, it } from 'vitest';

import { createSessionEngine } from '../adapters/mpp-session.js';
import { configure } from '../config.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import { Signer } from '../signer.js';

const RECIPIENT = 'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj';
type SessionStoreWithCapability = ReturnType<typeof createMemorySessionStore> & {
    readonly sessionStoreDurability?: 'durable-shared' | 'ephemeral';
};

function sessionGate() {
    return Gate.create(
        {
            amount: usd('1.00'),
            kind: 'session',
            name: 'stream',
            payTo: RECIPIENT,
            session: { unitPrice: 100n },
        },
        { accept: ['mpp'], payTo: RECIPIENT },
    );
}

async function configWithStore(sessionStore?: SessionStoreWithCapability) {
    return await configure({
        mpp: { challengeBindingSecret: 'session-store-test-secret', sessionStore },
        network: 'solana_devnet',
        operator: { recipient: RECIPIENT, signer: await Signer.generate() },
        replayStore: Store.memory(),
    });
}

describe('MPP session store construction', () => {
    it('fails closed outside localnet without an injected store', async () => {
        const config = await configWithStore();
        expect(() => createSessionEngine(config, sessionGate())).toThrow(
            /mpp\.sessionStore is required outside localnet/,
        );
    });

    it('rejects an unmarked injected store outside localnet', async () => {
        const { sessionStoreDurability: _ignored, ...store } = createMemorySessionStore() as SessionStoreWithCapability;
        const config = await configWithStore(store);
        expect(() => createSessionEngine(config, sessionGate())).toThrow(/explicitly declare durable shared/);
    });

    it('accepts an explicitly durable shared store outside localnet', async () => {
        const store = { ...createMemorySessionStore(), sessionStoreDurability: 'durable-shared' as const };
        const engine = createSessionEngine(await configWithStore(store), sessionGate());
        await expect(engine.receipt('unknown-channel')).resolves.toBeUndefined();
    });

    it('keeps the explicit localnet development fallback', async () => {
        const config = await configure({
            mpp: { challengeBindingSecret: 'session-store-test-secret' },
            network: 'solana_localnet',
            operator: { recipient: RECIPIENT, signer: await Signer.generate() },
        });
        const engine = createSessionEngine(config, sessionGate());
        await expect(engine.receipt('unknown-channel')).resolves.toBeUndefined();
    });
});
