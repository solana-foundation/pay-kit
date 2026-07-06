// Cross-process replay reservation.
//
// The `mppx` Store exposes only get/put/delete, so the charge replay guards
// serialize a "reject if consumed, else mark consumed" sequence with an
// in-process lock (see keyLock.ts). That closes the race within a single Node
// process, but two replicas sharing one Store still race across processes:
// each has its own lock, so both can pass the get() and both put().
//
// A production Store can close that cross-process window by backing the
// consumed marker with an ATOMIC put-if-absent (e.g. Redis `SET key val NX`).
// This module defines that optional capability and a `claimConsumed` helper
// that uses it when present and degrades to a plain get-then-put otherwise — so
// the same call site is correct on a single process (still guarded by the
// surrounding withKeyLock) and additionally cross-process safe when a reserving
// store is supplied.

import { Store } from 'mppx';

/**
 * A {@link Store.Store} that additionally supports an atomic reserve
 * (put-if-absent). `reserve(key)` MUST atomically insert a marker under `key`
 * only when it is absent, returning `true` when it created the marker (the
 * caller now owns the reservation) and `false` when a marker already existed.
 *
 * `ttlSeconds`, when provided, is a hint that the reservation may expire after
 * that many seconds — used by the x402 in-flight guard, whose duplicate window
 * is bounded by the transaction blockhash lifetime, so the marker need not live
 * forever. A Redis-backed implementation maps `reserve` to `SET key val NX`
 * (plus `EX ttlSeconds` when set); an in-memory one to a check-and-set on its
 * Map. Implementing it makes replay protection safe across processes/replicas,
 * not just within one Node process.
 */
export interface ReservingStore extends Store.Store {
    reserve(key: string, value?: unknown, ttlSeconds?: number): Promise<boolean>;
}

/** Whether `store` implements the atomic {@link ReservingStore.reserve}. */
export function isReservingStore(store: Store.Store): store is ReservingStore {
    return typeof (store as Partial<ReservingStore>).reserve === 'function';
}

/**
 * Atomically claim `key` as consumed. Returns `true` when the caller newly
 * claimed it and `false` when it was already claimed.
 *
 * When `store` implements {@link ReservingStore}, the claim is a single atomic
 * put-if-absent and is safe across processes/replicas. Otherwise it degrades to
 * a get-then-put, which is only race-free when the caller already serializes
 * concurrent claims for `key` within the process (the charge guards do, via
 * withKeyLock). Multi-replica deployments MUST supply a reserving store; see
 * SECURITY.md.
 *
 * This helper never takes a lock itself, so it is safe to call from inside a
 * withKeyLock section without re-entering it.
 *
 * On a claimed key that later proves invalid (e.g. the on-chain verify fails,
 * or the transaction never landed), the caller must release it with
 * `store.delete(key)` so an honest retry is not permanently bricked.
 */
export async function claimConsumed(store: Store.Store, key: string): Promise<boolean> {
    if (isReservingStore(store)) {
        return await store.reserve(key, true);
    }
    if (await store.get(key)) {
        return false;
    }
    await store.put(key, true);
    return true;
}
