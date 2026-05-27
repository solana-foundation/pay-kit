<?php

declare(strict_types=1);

namespace PayKit\Store;

/**
 * In-memory {@see Store} for tests and local development.
 *
 * The store is single-process. Multi-worker production servers must inject a
 * shared atomic backing store (Redis, Postgres, DynamoDB) instead, otherwise
 * replay protection is lost across the worker pool.
 */
final class MemoryStore implements Store
{
    /**
     * @var array<string, mixed>
     */
    private array $values = [];

    public function putIfAbsent(string $key, mixed $value): bool
    {
        if (array_key_exists($key, $this->values)) {
            return false;
        }
        $this->values[$key] = $value;
        return true;
    }
}
