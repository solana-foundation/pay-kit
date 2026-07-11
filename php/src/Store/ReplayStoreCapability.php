<?php

declare(strict_types=1);

namespace PayKit\Store;

/**
 * Explicit capability declaration for replay-protection stores.
 *
 * Non-localnet MPP servers fail closed unless their Store implements this
 * interface and returns true. A Store that does not implement this interface
 * is intentionally treated as unsafe until its author makes the durability
 * and cross-worker sharing guarantee explicit.
 */
interface ReplayStoreCapability
{
    /**
     * True only when atomic replay reservations are durable and shared across
     * every server worker that can accept the same payment credential.
     */
    public function providesDurableSharedReplayProtection(): bool;
}
