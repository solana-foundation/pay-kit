import { Store } from 'mppx';

import { withKeyLock } from './keyLock.js';

type AtomicStore = Store.Store & {
    update?<T>(
        key: string,
        fn: (current: unknown) => { op: 'noop'; result: T } | { op: 'set'; result: T; value: unknown },
    ): Promise<T>;
};

type ReplayRecord = {
    binding: string;
    leaseUntil: number;
    state: 'confirmed' | 'pending';
};

export type ReplayClaim = 'conflict' | 'pending' | 'reserved' | 'retry';
export type ReplayStatus = 'available' | 'conflict' | 'expired' | 'pending' | 'retry';

// Keep recovery outside the complete settlement window, including confirmation
// polling and post-confirmation account verification. This matches the Python
// adapter's worst-case lease and prevents a retry from overlapping its owner.
const PENDING_LEASE_MS = 21 * 60 * 1_000;

function isReplayRecord(value: unknown): value is ReplayRecord {
    if (typeof value !== 'object' || value === null) return false;
    const record = value as Partial<ReplayRecord>;
    return (
        typeof record.binding === 'string' &&
        typeof record.leaseUntil === 'number' &&
        (record.state === 'pending' || record.state === 'confirmed')
    );
}

/** Inspect a challenge-bound proof without renewing an expired settlement lease. */
export async function inspectReplayKey(store: Store.Store, key: string, binding: string): Promise<ReplayStatus> {
    const current = await store.get(key);
    if (current === null) return 'available';
    if (!isReplayRecord(current) || current.binding !== binding) return 'conflict';
    if (current.state === 'confirmed') return 'retry';
    return current.leaseUntil <= Date.now() ? 'expired' : 'pending';
}

/**
 * Reserve a proof for one challenge-bound settlement.
 *
 * An identical retry may resume confirmation and receipt construction, while
 * a different challenge attempting to reuse the same proof is rejected.
 */
export async function claimReplayKey(store: Store.Store, key: string, binding: string): Promise<ReplayClaim> {
    const now = Date.now();
    const fresh: ReplayRecord = { binding, leaseUntil: now + PENDING_LEASE_MS, state: 'pending' };
    const classify = (current: unknown): ReplayClaim => {
        if (current === null) return 'reserved';
        if (!isReplayRecord(current) || current.binding !== binding) return 'conflict';
        if (current.state === 'confirmed') return 'retry';
        return current.leaseUntil <= now ? 'reserved' : 'pending';
    };
    const atomicStore = store as AtomicStore;
    if (typeof atomicStore.update === 'function') {
        return await atomicStore.update(key, current => {
            const result = classify(current);
            return result === 'reserved' ? { op: 'set', result, value: fresh } : { op: 'noop', result };
        });
    }

    return await withKeyLock(key, async () => {
        const current = await store.get(key);
        const result = classify(current);
        if (result === 'reserved') await store.put(key, fresh);
        return result;
    });
}

/** Mark a challenge-bound proof as fully verified and receipt-ready. */
export async function confirmReplayKey(store: Store.Store, key: string, binding: string): Promise<void> {
    const current = await store.get(key);
    if (!isReplayRecord(current) || current.binding !== binding) {
        throw new Error('Replay reservation changed before settlement completed');
    }
    await store.put(key, { binding, leaseUntil: current.leaseUntil, state: 'confirmed' } satisfies ReplayRecord);
}

/** Atomically reserves a replay key, falling back to a process-local lock for legacy stores. */
export async function reserveReplayKey(store: Store.Store, key: string): Promise<boolean> {
    const atomicStore = store as AtomicStore;
    if (typeof atomicStore.update === 'function') {
        return await atomicStore.update(key, current =>
            current === null ? { op: 'set', result: true, value: true } : { op: 'noop', result: false },
        );
    }

    // Older custom stores expose only get/put/delete. This closes the race
    // within one runtime; multi-process deployments must provide update().
    return await withKeyLock(key, async () => {
        if ((await store.get(key)) !== null) return false;
        await store.put(key, true);
        return true;
    });
}
