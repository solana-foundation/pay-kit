// Regression tests for the cross-process replay reservation (P3).
//
// The charge replay guards mark a signature consumed with `claimConsumed`.
// With the base mppx Store (get/put/delete), a concurrent pair of claims can
// BOTH succeed — the `await` between get() and put() interleaves — which is
// exactly why the guards need an in-process withKeyLock and why two replicas
// sharing one Store still race across processes. A Store that implements the
// atomic reserve capability closes that window: the check-and-set is a single
// atomic op, so concurrent claims yield exactly one winner without any lock.

import { describe, expect, test } from 'vitest';

import { claimConsumed, isReservingStore, type ReservingStore } from '../server/replayReserve.js';

/** Base mppx-shaped Store (get/put/delete) with no atomic reserve. */
function memoryStore() {
    const map = new Map<string, unknown>();
    return {
        get: (key: string) => Promise.resolve(map.get(key) ?? null),
        put: (key: string, value: unknown) => {
            map.set(key, value);
            return Promise.resolve();
        },
        delete: (key: string) => {
            map.delete(key);
            return Promise.resolve();
        },
    };
}

/**
 * A reserving Store: `reserve` is an atomic check-and-set (no await between the
 * has() and the set(), so it is race-free on the single-threaded event loop),
 * modeling a Redis `SET key val NX`.
 */
function reservingStore(): ReservingStore {
    const map = new Map<string, unknown>();
    return {
        get: (key: string) => Promise.resolve(map.get(key) ?? null),
        put: (key: string, value: unknown) => {
            map.set(key, value);
            return Promise.resolve();
        },
        delete: (key: string) => {
            map.delete(key);
            return Promise.resolve();
        },
        reserve: (key: string, value: unknown = true) => {
            if (map.has(key)) return Promise.resolve(false);
            map.set(key, value);
            return Promise.resolve(true);
        },
    };
}

describe('isReservingStore', () => {
    test('detects the atomic reserve capability', () => {
        expect(isReservingStore(reservingStore())).toBe(true);
        expect(isReservingStore(memoryStore())).toBe(false);
    });
});

describe('claimConsumed', () => {
    test('a reserving store yields exactly one winner under concurrency', async () => {
        const store = reservingStore();
        const results = await Promise.all([
            claimConsumed(store, 'sig'),
            claimConsumed(store, 'sig'),
            claimConsumed(store, 'sig'),
        ]);
        expect(results.filter(Boolean)).toHaveLength(1);
    });

    test('a NON-reserving store races: concurrent unguarded claims both win', async () => {
        // This is the cross-process window the reserve capability closes. The
        // charge guards compensate in-process with withKeyLock; without an
        // atomic reserve, replicas sharing this store race.
        const store = memoryStore();
        const results = await Promise.all([claimConsumed(store, 'sig'), claimConsumed(store, 'sig')]);
        expect(results).toEqual([true, true]);
    });

    test('sequential replays are rejected on both store kinds', async () => {
        for (const store of [reservingStore(), memoryStore()]) {
            expect(await claimConsumed(store, 'sig')).toBe(true);
            expect(await claimConsumed(store, 'sig')).toBe(false);
        }
    });

    test('a released (deleted) key can be reclaimed', async () => {
        const store = reservingStore();
        expect(await claimConsumed(store, 'sig')).toBe(true);
        await store.delete('sig');
        expect(await claimConsumed(store, 'sig')).toBe(true);
    });
});
