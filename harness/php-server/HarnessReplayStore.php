<?php

declare(strict_types=1);

namespace PayKitHarness\PhpServer;

use PayKit\Store\FileStore;
use PayKit\Store\ReplayStoreCapability;
use PayKit\Store\Store;

/** Test-only replay store shared by every PHP worker in one harness run. */
final class HarnessReplayStore implements Store, ReplayStoreCapability
{
    private FileStore $store;

    public function __construct(string $directory)
    {
        $this->store = new FileStore($directory);
    }

    public function putIfAbsent(string $key, mixed $value): bool
    {
        return $this->store->putIfAbsent($key, $value);
    }

    public function providesDurableSharedReplayProtection(): bool
    {
        // The harness injects one run-scoped directory shared across workers.
        return true;
    }
}
