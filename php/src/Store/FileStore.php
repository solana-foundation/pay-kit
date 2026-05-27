<?php

declare(strict_types=1);

namespace PayKit\Store;

use RuntimeException;

/**
 * Filesystem-backed {@see Store} using atomic exclusive file creation.
 *
 * Useful for examples, local development, and single-host PHP-FPM setups where
 * a process restart between requests must still preserve replay protection.
 * For multi-host production deployments, inject a {@see Store} backed by a
 * shared database, Redis, or another atomic cross-worker store instead.
 *
 * Each key is hashed (SHA-256) to a flat filename so callers can pass
 * arbitrary key strings (including ones containing path separators) without
 * worrying about filesystem-safe encodings.
 */
final class FileStore implements Store
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($this->directory) && !mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new RuntimeException("Unable to create replay store directory: {$this->directory}");
        }
    }

    public function putIfAbsent(string $key, mixed $value): bool
    {
        $path = $this->pathForKey($key);
        $handle = @fopen($path, 'x');
        if ($handle === false) {
            if (is_file($path)) {
                return false;
            }
            throw new RuntimeException("Unable to create replay marker: $path");
        }

        try {
            // The marker file's contents are not consulted on read; the
            // file's existence is the entire signal. Persist the key for
            // operator-side debugging only.
            fwrite($handle, $key . "\n");
        } finally {
            fclose($handle);
        }

        return true;
    }

    private function pathForKey(string $key): string
    {
        return rtrim($this->directory, DIRECTORY_SEPARATOR)
            . DIRECTORY_SEPARATOR
            . hash('sha256', $key)
            . '.consumed';
    }
}
