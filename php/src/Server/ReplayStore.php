<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * Records consumed settlement references to prevent credential replay.
 *
 * Implementations must be safe for concurrent use across all workers that
 * share a settlement origin. The interface is intentionally minimal: a single
 * atomic "consume this key" primitive is enough to defeat replay for both
 * pull-mode (server-broadcast signature) and push-mode (client-broadcast
 * signature) credentials.
 */
interface ReplayStore
{
    /**
     * Mark a replay key as consumed.
     *
     * Returns true when this call atomically inserted the key, or false when
     * the key was already present. Implementations must never return true
     * twice for the same key, even under concurrent callers.
     */
    public function consume(string $key): bool;
}
