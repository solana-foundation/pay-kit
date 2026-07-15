<?php

declare(strict_types=1);

namespace PayKit\Store;

/**
 * Centralizes the fail-closed replay-store capability check.
 */
final class ReplayStoreValidator
{
    public static function isDurableShared(Store $store): bool
    {
        $declared = false;

        if ($store instanceof DurableStore) {
            $declared = true;
            if (!$store->isDurable()) {
                return false;
            }
        }

        if ($store instanceof ReplayStoreCapability) {
            $declared = true;
            if (!$store->providesDurableSharedReplayProtection()) {
                return false;
            }
        }

        return $declared;
    }
}
