<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402;

use PayKit\Store\MemoryStore;
use PayKit\Store\ReplayStoreCapability;
use PayKit\Store\Store;

/**
 * Contract test double. This class does not model production durability; it
 * only proves that Adapter honors an explicitly declared store capability.
 */
final class ExplicitCapabilityTestReplayStore implements Store, ReplayStoreCapability
{
    private MemoryStore $store;

    public function __construct()
    {
        $this->store = new MemoryStore();
    }

    public function putIfAbsent(string $key, mixed $value): bool
    {
        return $this->store->putIfAbsent($key, $value);
    }

    public function providesDurableSharedReplayProtection(): bool
    {
        return true;
    }
}
