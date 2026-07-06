// Eviction of idle per-channel lock entries in the in-memory session store.
//
// The store serializes `updateChannel` calls per channel id via a promise
// chain keyed on the id. Without eviction that keyed map grows one entry per
// ever-seen channel id and is never reclaimed, an unbounded memory footprint
// under a stream of distinct ids. Eviction deletes a channel's chain entry
// once it settles and is still the tail (no queued successor), so the map
// returns to empty when idle while queued operations stay serialized.

import { describe, expect, test } from 'vitest';

import { type ChannelState, createMemorySessionStore } from '../server/session/store.js';

// The store exposes a test-only accessor for the size of its internal
// per-channel lock map. It is not part of `SessionStore`; production callers
// never see it.
type StoreWithLockProbe = ReturnType<typeof createMemorySessionStore> & {
    readonly _lockMapSize: () => number;
};

function makeState(channelId: string, deposit: bigint): ChannelState {
    return {
        channelId,
        authorizedSigner: '11111111111111111111111111111111',
        deposit,
        cumulative: 0n,
        finalized: false,
        nextDeliverySequence: 0n,
        pendingDeliveries: [],
        committedDeliveries: [],
    };
}

describe('memory session store lock eviction', () => {
    test('idle per-channel lock entries are evicted after updates settle', async () => {
        const store = createMemorySessionStore() as StoreWithLockProbe;

        // Sequential cycles across many distinct channel ids.
        const sequentialIds = 200;
        for (let i = 0; i < sequentialIds; i++) {
            const id = `seq-${i}`;
            await store.updateChannel(id, () => makeState(id, 1n));
        }

        // Concurrent bursts across many distinct channel ids: each id gets a
        // burst that serializes, then goes idle.
        const concurrentIds = 100;
        const perId = 8;
        const tasks: Promise<ChannelState>[] = [];
        for (let i = 0; i < concurrentIds; i++) {
            const id = `con-${i}`;
            for (let j = 0; j < perId; j++) {
                tasks.push(
                    store.updateChannel(id, current => {
                        if (!current) return makeState(id, 1n);
                        return { ...current, cumulative: current.cumulative + 1n };
                    }),
                );
            }
        }
        await Promise.all(tasks);

        // A microtask turn lets the tail-eviction `.then` callbacks run.
        await Promise.resolve();

        expect(store._lockMapSize()).toBe(0);

        const all = await store.listChannels();
        expect(all.length).toBe(sequentialIds + concurrentIds);
    });

    test('eviction keeps concurrent updates on one channel serialized', async () => {
        const store = createMemorySessionStore() as StoreWithLockProbe;
        await store.updateChannel('c1', () => makeState('c1', 0n));

        // Race many concurrent increments for a single channel. If eviction let
        // two updates run unserialized, some increments would read a stale
        // value and the final cumulative would be below the worker count.
        const workers = 64;
        const tasks: Promise<ChannelState>[] = [];
        for (let i = 0; i < workers; i++) {
            tasks.push(
                store.updateChannel('c1', current => {
                    const base = current ?? makeState('c1', 0n);
                    return { ...base, cumulative: base.cumulative + 1n };
                }),
            );
        }
        await Promise.all(tasks);
        await Promise.resolve();

        const stored = await store.getChannel('c1');
        expect(stored?.cumulative).toBe(BigInt(workers));
        expect(store._lockMapSize()).toBe(0);
    });
});
