<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * In-memory replay store for local development and tests.
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
