import type { Store } from 'mppx';
import { describe, expect, it } from 'vitest';

import {
    createAtomicReplayStoreView,
    type ReplayStore,
    type ReplayStoreCapability,
    resolveReplayStore,
} from '../server/store.js';

function replayStore(capabilities: ReplayStoreCapability = {}): ReplayStore {
    const values = new Map<string, unknown>();
    return {
        delete: async key => {
            values.delete(key);
        },
        get: async key => (values.get(key) ?? null) as never,
        ...capabilities,
        put: async (key, value) => {
            values.set(key, value);
        },
        putIfAbsent: async (key, value) => {
            if (values.has(key)) return false;
            values.set(key, value);
            return true;
        },
    };
}

const LEGACY_STORE: Store.Store = {
    async delete() {},
    async get() {
        return null;
    },
    async put() {},
};

describe('createAtomicReplayStoreView', () => {
    it('preserves capability declarations and atomic reservation', async () => {
        const view = createAtomicReplayStoreView(replayStore({ isDurable: true, isShared: true }));

        expect(view.isDurable).toBe(true);
        expect(view.isShared).toBe(true);
        await expect(view.putIfAbsent('reservation', true)).resolves.toBe(true);
        await expect(view.putIfAbsent('reservation', true)).resolves.toBe(false);
    });
});

describe('resolveReplayStore', () => {
    it.each([
        ['isShared-only', replayStore({ isShared: true })],
        ['isDurable-only', replayStore({ isDurable: true })],
        ['unknown capabilities', replayStore()],
        ['non-atomic store', LEGACY_STORE],
    ])('rejects a production store with %s', (_label, store) => {
        expect(() => resolveReplayStore(store, false, 'charge')).toThrow(
            /atomic putIfAbsent and report isShared=true and isDurable=true/,
        );
    });

    it('accepts an atomic store with both production capabilities', () => {
        const store = replayStore({ isDurable: true, isShared: true });

        expect(resolveReplayStore(store, false, 'subscription')).toBe(store);
    });
});
