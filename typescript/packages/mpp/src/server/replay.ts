import { Store } from 'mppx';

import { withKeyLock } from './keyLock.js';

type AtomicStore = Store.Store & {
    update?<T>(
        key: string,
        fn: (current: unknown | null) => { op: 'noop'; result: T } | { op: 'set'; result: T; value: unknown },
    ): Promise<T>;
};

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
