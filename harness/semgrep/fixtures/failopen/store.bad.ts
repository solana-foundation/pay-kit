// BAD: replay/session store defaults to an in-memory impl when the configured
// shared backing is absent, or is hard-wired with no injectable alternative.

import { createMemorySessionStore } from './store';

interface EngineConfig {
    store?: SessionStore;
}

export function createEngineNullish(config: EngineConfig) {
    // nullish default => multi-instance fails open
    const store = config.store ?? createMemorySessionStore();
    return { store };
}

export function createEngineOr(config: EngineConfig) {
    const store = config.store || createMemorySessionStore();
    return { store };
}

export function createEngineUnconditional() {
    // hard-wired, no config hook for a shared store
    const store = createMemorySessionStore();
    return { store };
}
