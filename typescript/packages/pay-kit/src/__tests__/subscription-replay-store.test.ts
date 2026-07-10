import { describe, expect, it } from 'vitest';

import { createUnsafeMemorySubscriptionReplayStore } from '../subscription-replay-store.js';

describe('subscription replay store', () => {
    it('reserves a key exactly once and preserves the first value', async () => {
        const store = createUnsafeMemorySubscriptionReplayStore();

        await expect(
            Promise.all([store.reserve('activation', 'first'), store.reserve('activation', 'second')]),
        ).resolves.toEqual([true, false]);
        await expect(store.get('activation')).resolves.toBe('first');
    });

    it('allows a key to be reserved again only after deletion', async () => {
        const store = createUnsafeMemorySubscriptionReplayStore();

        await expect(store.reserve('activation')).resolves.toBe(true);
        await store.delete('activation');
        await expect(store.reserve('activation')).resolves.toBe(true);
    });

    it('shares one atomic namespace with charge replay reservations', async () => {
        const store = createUnsafeMemorySubscriptionReplayStore();

        await expect(store.putIfAbsent('credential', 'charge')).resolves.toBe(true);
        await expect(store.reserve('credential', 'subscription')).resolves.toBe(false);
        await expect(store.get('credential')).resolves.toBe('charge');
    });
});
