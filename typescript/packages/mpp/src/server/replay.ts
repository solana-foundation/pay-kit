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
    /**
     * On the ledger key: the grant in progress. On the legacy key: the grant
     * that confirmed it, written in the same atomic step. A replica on the
     * previous release confirms the legacy key without one, so a confirmed
     * legacy key proves this grant's ownership only when the ids match.
     */
    grant?: string;
    leaseUntil: number;
    /**
     * `granting`: the payment landed and its grant began, which confirms the
     * previous release's key and then this one. The legacy key's
     * pending-to-confirmed step is the single winner both releases share.
     */
    state: 'confirmed' | 'granting' | 'pending';
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
        (record.state === 'pending' || record.state === 'granting' || record.state === 'confirmed')
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
    const classify = (current: unknown): ReplayClaim => {
        if (current === null) return 'reserved';
        if (!isReplayRecord(current) || current.binding !== binding) return 'conflict';
        if (current.state === 'confirmed') return 'retry';
        return current.leaseUntil <= now ? 'reserved' : 'pending';
    };
    // Taking over an expired lease keeps a grant in progress, and its id,
    // marked as one.
    const fresh = (current: unknown): ReplayRecord =>
        isReplayRecord(current) && current.state === 'granting'
            ? { binding, grant: current.grant, leaseUntil: now + PENDING_LEASE_MS, state: 'granting' }
            : { binding, leaseUntil: now + PENDING_LEASE_MS, state: 'pending' };
    const atomicStore = store as AtomicStore;
    if (typeof atomicStore.update === 'function') {
        return await atomicStore.update(key, current => {
            const result = classify(current);
            return result === 'reserved' ? { op: 'set', result, value: fresh(current) } : { op: 'noop', result };
        });
    }

    return await withKeyLock(key, async () => {
        const current = await store.get(key);
        const result = classify(current);
        if (result === 'reserved') await store.put(key, fresh(current));
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
        if (
            !isReplayRecord(current) ||
            current.binding !== binding ||
            (current.state !== 'pending' && current.state !== 'granting')
        ) {
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

/**
 * Mark a reservation whose payment landed as being granted, before the grant
 * takes any other key, and return the grant's id: a fresh one, or the one an
 * earlier attempt of this grant recorded. `undefined` unless the record is
 * pending or granting under `binding`.
 */
export async function beginGrantReplayKey(
    store: Store.Store,
    key: string,
    binding: string,
): Promise<string | undefined> {
    const fresh = crypto.randomUUID();
    const begin = (current: unknown) => {
        if (
            !isReplayRecord(current) ||
            current.binding !== binding ||
            (current.state !== 'pending' && current.state !== 'granting')
        ) {
            return { op: 'noop' as const, result: undefined };
        }
        const grant = current.state === 'granting' && current.grant ? current.grant : fresh;
        return {
            op: 'set' as const,
            result: grant,
            value: { ...current, grant, state: 'granting' } satisfies ReplayRecord,
        };
    };
    const atomicStore = store as AtomicStore;
    if (typeof atomicStore.update === 'function') return await atomicStore.update(key, begin);
    return await withKeyLock(key, async () => {
        const change = begin(await store.get(key));
        if (change.op === 'set') await store.put(key, change.value);
        return change.result;
    });
}

/**
 * Confirm the previous release's key for `grant`, in one atomic step: the
 * single-winner transition a replica on that release also takes. `true` when
 * this grant confirmed it, now or in an earlier attempt; `false` when it is
 * confirmed by anyone else (a previous-release replica) or not held under
 * `binding`.
 */
export async function confirmLegacyForGrant(
    store: Store.Store,
    key: string,
    binding: string,
    grant: string,
): Promise<boolean> {
    const confirm = (current: unknown) => {
        if (!isReplayRecord(current) || current.binding !== binding) {
            return { op: 'noop' as const, result: false };
        }
        if (current.state === 'confirmed') return { op: 'noop' as const, result: current.grant === grant };
        return {
            op: 'set' as const,
            result: true,
            value: { ...current, grant, state: 'confirmed' } satisfies ReplayRecord,
        };
    };
    const atomicStore = store as AtomicStore;
    if (typeof atomicStore.update === 'function') return await atomicStore.update(key, confirm);
    return await withKeyLock(key, async () => {
        const change = confirm(await store.get(key));
        if (change.op === 'set') await store.put(key, change.value);
        return change.result;
    });
}

/**
 * Whether the confirmed legacy key was confirmed by the grant the ledger
 * record has in progress: this release's own unfinished grant.
 */
export async function ownsConfirmedLegacy(
    store: Store.Store,
    ledgerKey: string,
    legacyKey: string,
    binding: string,
): Promise<boolean> {
    const ledger = await store.get(ledgerKey);
    const legacy = await store.get(legacyKey);
    return (
        isReplayRecord(ledger) &&
        isReplayRecord(legacy) &&
        ledger.binding === binding &&
        legacy.binding === binding &&
        ledger.state === 'granting' &&
        legacy.state === 'confirmed' &&
        ledger.grant !== undefined &&
        legacy.grant === ledger.grant
    );
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
 * Key under which MPP charge claimed signatures before the shared ledger. The
 * x402 adapter kept no store record then, so it has no legacy key.
 *
 * Every claim also takes this key, holding the same record, so that during a
 * rolling upgrade a replica still running the previous release (which claims
 * and checks only this key) sees a payment this release accepted, and the
 * other way round.
 */
export function legacyConsumedSignatureKey(signature: string): string {
    return `solana-charge:consumed:${signature}`;
}

/**
 * Whether `signature` is held under the legacy MPP charge key only, by a
 * replica running the previous release or by this one before it upgraded.
 * This release's own claims hold the ledger key too, so they are not
 * reported. Read only and fail closed: such a signature stays consumed, it is
 * never migrated or claimed again.
 */
export async function consumedBeforeLedger(store: Store.Store, signature: string): Promise<boolean> {
    if ((await store.get(consumedSignatureKey(signature))) !== null) return false;
    return (await store.get(legacyConsumedSignatureKey(signature))) !== null;
}

/**
 * Atomically claim `signature` in the shared consumed-signature ledger.
 * `false` means an earlier presentation, through any protocol or release,
 * claimed it.
 *
 * The legacy key comes first, taken the way the previous release takes it, so
 * a replica on that release contends on the very same key and at most one of
 * them wins. A refused ledger claim gives the legacy key back.
 */
export async function claimConsumedSignature(store: Store.Store, signature: string): Promise<boolean> {
    const legacy = legacyConsumedSignatureKey(signature);
    if (!(await reserveReplayKey(store, legacy))) return false;
    if (await reserveReplayKey(store, consumedSignatureKey(signature))) return true;
    await store.delete(legacy);
    return false;
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
