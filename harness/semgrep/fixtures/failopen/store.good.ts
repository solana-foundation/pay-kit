// GOOD: a shared store is required; mis-configuration fails closed. The
// in-memory impl is only ever constructed behind an explicit opt-in flag, and
// the binding is not named like a replay/session store default.

import { createMemorySessionStore } from './store';

interface EngineConfig {
    store?: SessionStore;
    allowSingleProcessMemoryStore?: boolean;
}

export function createEngine(config: EngineConfig) {
    if (!config.store && !config.allowSingleProcessMemoryStore) {
        throw new Error('a shared SessionStore is required outside single-process deploys');
    }
    const backing = config.store ?? explicitSingleProcess(config);
    return { store: backing };
}

// Explicit opt-in helper — the memory store is returned from a clearly named
// function, not silently defaulted in a `?? createMemory...()` fallback.
function explicitSingleProcess(config: EngineConfig): SessionStore {
    return createMemorySessionStore();
}
