import type { SessionStore } from './store.js';

const MAX_TIMER_DELAY_MS = 2_147_483_647;

/** Idle-close watchdog backed by persisted channel activity. */
export interface Lifecycle {
    /** Cancel the idle timer for `channelId`. */
    removeChannel(channelId: string): void;
    /** Cancel every outstanding timer. */
    shutdown(): void;
    /** Reset the idle timer using the channel's negotiated timeout. */
    touch(channelId: string, idleTimeoutSeconds?: number): void;
}

/**
 * Creates an idle watchdog that restores open channels from the store and
 * atomically rechecks their activity before beginning close.
 */
export function createLifecycle(
    store: SessionStore,
    closeOnIdle: (channelId: string) => Promise<void> | void,
    idleTimeoutMs: number,
): Lifecycle {
    const timers = new Map<string, NodeJS.Timeout>();

    function clear(channelId: string): void {
        const handle = timers.get(channelId);
        if (handle !== undefined) {
            clearTimeout(handle);
            timers.delete(channelId);
        }
    }

    async function closeIfIdle(channelId: string): Promise<void> {
        timers.delete(channelId);
        let shouldClose = false;
        let nextDeadline: number | undefined;
        await store.updateChannel(channelId, current => {
            if (!current) throw new Error(`Channel ${channelId} not found`);
            if (current.sealed || current.closeRequestedAt !== undefined) return current;
            const timeoutSeconds = current.idleTimeoutSeconds;
            if (!timeoutSeconds || !current.lastActivityAt) return current;
            const deadline = current.lastActivityAt + timeoutSeconds * 1_000;
            if (Date.now() < deadline) {
                nextDeadline = deadline;
                return current;
            }
            shouldClose = true;
            return { ...current, closeRequestedAt: BigInt(Math.floor(Date.now() / 1_000)) };
        });
        if (nextDeadline !== undefined) {
            schedule(channelId, nextDeadline);
        } else if (shouldClose) {
            await closeOnIdle(channelId);
        }
    }

    function schedule(channelId: string, deadlineMs: number): void {
        const remainingMs = deadlineMs - Date.now();
        if (remainingMs <= 0) {
            void closeIfIdle(channelId).catch(() => undefined);
            return;
        }
        const handle = setTimeout(
            () => {
                if (Date.now() < deadlineMs) schedule(channelId, deadlineMs);
                else void closeIfIdle(channelId).catch(() => undefined);
            },
            Math.min(remainingMs, MAX_TIMER_DELAY_MS),
        );
        if (typeof handle.unref === 'function') handle.unref();
        timers.set(channelId, handle);
    }

    function scheduleFromStore(channelId: string, fallbackSeconds?: number): void {
        void store
            .getChannel(channelId)
            .then(state => {
                if (!state || state.sealed || state.closeRequestedAt !== undefined) return;
                const seconds = state.idleTimeoutSeconds ?? fallbackSeconds;
                if (!seconds || seconds <= 0) return;
                schedule(channelId, (state.lastActivityAt ?? Date.now()) + seconds * 1_000);
            })
            .catch(() => undefined);
    }

    void store
        .listChannels({ sealed: false })
        .then(channels => {
            for (const channel of channels) scheduleFromStore(channel.channelId);
        })
        .catch(() => undefined);

    return {
        removeChannel(channelId) {
            clear(channelId);
        },
        shutdown() {
            for (const handle of timers.values()) clearTimeout(handle);
            timers.clear();
        },
        touch(channelId, idleTimeoutSeconds) {
            const fallbackSeconds = idleTimeoutSeconds === undefined ? idleTimeoutMs / 1_000 : idleTimeoutSeconds;
            if (fallbackSeconds <= 0) return;
            clear(channelId);
            scheduleFromStore(channelId, fallbackSeconds);
        },
    };
}
