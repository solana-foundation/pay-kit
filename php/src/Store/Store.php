<?php

declare(strict_types=1);

namespace PayKit\Store;

/**
 * Atomic replay-protection store interface.
 *
 * Mirrors the Ruby `Mpp::Store` and Rust `mpp::Store` abstractions. The
 * `SolanaChargeHandler` calls `putIfAbsent` once per settled signature to
 * guarantee at-most-once settlement under retries, restarts, and concurrent
 * requests. Implementations must be safe to call from multiple processes when
 * deployed in a multi-worker server (Redis, Postgres, etc.); the
 * {@see MemoryStore} bundled with this SDK is single-process only.
 */
interface Store
{
    /**
     * Insert `$value` only if `$key` does not exist.
     *
     * Returns true on insert, false if the key was already present. Must be
     * atomic with respect to concurrent callers. The handler treats a false
     * return as a replay attempt and rejects the credential.
     */
    public function putIfAbsent(string $key, mixed $value): bool;
}
