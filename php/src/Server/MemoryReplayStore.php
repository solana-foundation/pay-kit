<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * In-memory replay store for single-process tests only.
 *
 * Do not use this as a per-request default in PHP-FPM or other multi-worker
 * deployments because the array dies with the process. Use FileReplayStore,
 * Redis, SQL, or another shared atomic store for real server handling.
 */
final class MemoryReplayStore implements ReplayStore
{
    /** @var array<string, true> */
    private array $consumed = [];

    public function consume(string $key): bool
    {
        if (isset($this->consumed[$key])) {
            return false;
        }

        $this->consumed[$key] = true;
        return true;
    }
}
