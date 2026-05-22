<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * Records consumed settlement references to prevent credential replay.
 */
interface ReplayStore
{
    /**
     * Mark a replay key as consumed.
     *
     * Returns true when this call consumed the key, or false when it was
     * already present.
     */
    public function consume(string $key): bool;
}
