// Per-key async serialization.
//
// Concurrent calls with the same key run one at a time (queued); different keys
// run in parallel. Used to close the check-then-act replay window in charge
// signature verification: the `mppx` `Store` exposes only get/put/delete with
// no atomic put-if-absent, so the "reject if already consumed, else mark
// consumed" sequence has to be serialized in process.
//
// Scope: this serializes within a single Node process only. Deployments that
// run more than one process or replica sharing one `Store` still race across
// processes; those need the `Store` itself to back the consumed marker with an
// atomic reserve (e.g. Redis `SET key val NX`). See SECURITY.md.
const locks = new Map<string, Promise<unknown>>();

export function withKeyLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const previous = locks.get(key) ?? Promise.resolve();
    // Run `fn` after the previous holder settles, whichever way it settled.
    // Call `fn()` explicitly (rather than passing it as the handler) so it never
    // receives a settled value or rejection reason as an argument, even if a
    // future change lets `previous` reject.
    const current = previous.then(
        () => fn(),
        () => fn(),
    );
    // The next waiter chains on a tail that never rejects, so one failure does
    // not poison the queue for the same key.
    const tail = current.then(
        () => undefined,
        () => undefined,
    );
    locks.set(key, tail);
    void tail.then(() => {
        if (locks.get(key) === tail) {
            locks.delete(key);
        }
    });
    return current;
}
