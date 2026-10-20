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

/**
 * Consume a verified charge exactly once, including when expired-lease owners
 * finish concurrently. Atomic stores coordinate across processes; get/put-only
 * stores are safe only within a single process.
 */
export async function consumeReplayKey(store: Store.Store, key: string, binding: string): Promise<boolean> {
    const consume = (current: unknown) => {
        if (!isReplayRecord(current) || current.binding !== binding || current.state !== 'pending') {
            return { op: 'noop' as const, result: false };
        }
        return {
            op: 'set' as const,
            result: true,
            value: { ...current, state: 'confirmed' } satisfies ReplayRecord,
        };
    };
    const atomicStore = store as AtomicStore;
    if (typeof atomicStore.update === 'function') return await atomicStore.update(key, consume);
    return await withKeyLock(key, async () => {
        const change = consume(await store.get(key));
        if (change.op === 'set') await store.put(key, change.value);
        return change.result;
    });
}

/** Mark a challenge-bound subscription proof as fully verified and receipt-ready. */
export async function confirmReplayKey(store: Store.Store, key: string, binding: string): Promise<void> {
    const current = await store.get(key);
    if (!isReplayRecord(current) || current.binding !== binding) {
        throw new Error('Replay reservation changed before settlement completed');
    }
    await store.put(key, { binding, leaseUntil: current.leaseUntil, state: 'confirmed' } satisfies ReplayRecord);
}

/**
 * Key of a Solana transaction signature in the protocol-independent ledger of
 * payments that already authorized a protected response.
 *
 * MPP charge (pull and push) and PayKit's x402 `exact` adapter all claim here,
 * so one on-chain payment authorizes one request whichever protocol presents
 * it: a transaction settled through MPP cannot be presented again as an x402
 * payment on a gate sharing the store, and vice versa. The key is the
 * signature alone, matching the other PayKit SDKs.
 */
export function consumedSignatureKey(signature: string): string {
    return `solana:consumed-signature:${signature}`;
}

/**
 * Whether `signature` was claimed under the pre-ledger MPP charge key
 * (`solana-charge:consumed:<sig>`), by a replica running an older release or
 * before this one upgraded. Read only and fail closed: such a signature stays
 * consumed, it is never migrated or claimed again. The x402 adapter kept no
 * store record before the ledger, so it has no legacy key.
 */
export async function consumedBeforeLedger(store: Store.Store, signature: string): Promise<boolean> {
    return (await store.get(`solana-charge:consumed:${signature}`)) !== null;
}

/**
 * Atomically claim `signature` in the shared consumed-signature ledger.
 * `false` means an earlier presentation, through any protocol, claimed it.
 */
export async function claimConsumedSignature(store: Store.Store, signature: string): Promise<boolean> {
    if (await consumedBeforeLedger(store, signature)) return false;
    return await reserveReplayKey(store, consumedSignatureKey(signature));
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
