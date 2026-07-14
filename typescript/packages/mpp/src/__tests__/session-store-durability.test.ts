// Regression tests for the low-level session() store durability guard.
//
// A direct `@solana/mpp` `solana.session()` consumer must never silently get a
// process-local in-memory store outside a single-process dev network. The guard
// mirrors the replay-store policy: durable-shared everywhere, localnet free,
// devnet behind the PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE opt-in, mainnet closed.

import { afterEach, beforeEach, describe, expect, test } from 'vitest';

import { ConfigurationError, session } from '../server/Session.js';
import { createMemorySessionStore, type SessionStore } from '../server/session/store.js';

const OPERATOR = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const RECIPIENT = '5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h';

function baseParams(network: string) {
    return {
        cap: 1_000_000n,
        currency: 'USDC',
        decimals: 6,
        network,
        operator: OPERATOR,
        pricing: {},
        recipient: RECIPIENT,
    } as const;
}

/** A store that affirms durable shared storage without being the SDK memory store. */
function durableSessionStore(): SessionStore {
    const inner = createMemorySessionStore();
    return {
        deleteChannel: id => inner.deleteChannel(id),
        getChannel: id => inner.getChannel(id),
        listChannels: filter => inner.listChannels(filter),
        markSealed: id => inner.markSealed(id),
        sessionStoreDurability: 'durable-shared',
        updateChannel: (id, mutator) => inner.updateChannel(id, mutator),
    };
}

describe('session() store durability guard', () => {
    const prior = process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
    beforeEach(() => {
        delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
    });
    afterEach(() => {
        if (prior === undefined) delete process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE;
        else process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = prior;
    });

    test('mainnet session() with no store fails closed', () => {
        for (const network of ['mainnet', 'mainnet-beta', 'MAINNET']) {
            expect(() => session(baseParams(network))).toThrow(ConfigurationError);
            expect(() => session(baseParams(network))).toThrow(/durable shared session store on mainnet/);
        }
    });

    test('mainnet session() rejects an explicit process-local memory store', () => {
        expect(() => session({ ...baseParams('mainnet'), store: createMemorySessionStore() })).toThrow(
            ConfigurationError,
        );
        // The env/param opt-in cannot relax mainnet.
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        expect(() => session({ ...baseParams('mainnet'), store: createMemorySessionStore() })).toThrow(
            ConfigurationError,
        );
        expect(() => session({ ...baseParams('mainnet'), allowUnsafeMemoryStore: true })).toThrow(ConfigurationError);
    });

    test('devnet with no store fails closed without the opt-in', () => {
        expect(() => session(baseParams('devnet'))).toThrow(/durable shared session store outside localnet/);
    });

    test('devnet permits the process-local store under the env opt-in', () => {
        process.env.PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE = '1';
        expect(() => session(baseParams('devnet'))).not.toThrow();
    });

    test('devnet permits the process-local store under the param opt-in', () => {
        expect(() => session({ ...baseParams('devnet'), allowUnsafeMemoryStore: true })).not.toThrow();
    });

    test('localnet permits a process-local store with no opt-in', () => {
        expect(() => session(baseParams('localnet'))).not.toThrow();
        expect(() => session({ ...baseParams('localnet'), store: createMemorySessionStore() })).not.toThrow();
    });

    test('a durable-shared store is permitted on mainnet', () => {
        expect(() => session({ ...baseParams('mainnet'), store: durableSessionStore() })).not.toThrow();
    });
});
