<?php

declare(strict_types=1);

namespace PayKit\Store;

/**
 * Compatibility production replay-store capability.
 *
 * Implement this interface only when putIfAbsent is atomic across every
 * process that accepts credentials and replay markers survive the relevant
 * process lifetime. MPP accepts this contract alongside
 * {@see ReplayStoreCapability}; if an implementation declares both, both
 * capability methods must return true.
 */
interface DurableStore extends Store
{
    public function isDurable(): bool;
}
