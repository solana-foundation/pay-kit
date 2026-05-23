<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use RuntimeException;

/**
 * Filesystem-backed replay store using atomic exclusive file creation.
 *
 * Useful for examples, local development, and single-host PHP-FPM setups
 * where all workers share a writable directory. Multi-host production
 * deployments should provide a ReplayStore backed by a shared database,
 * Redis, or another atomic cross-worker store.
 *
 * Atomicity comes from `fopen($path, 'x')`, which fails when the file
 * already exists. The marker filename is the SHA-256 of the replay key so
 * that signatures or other arbitrary strings produce safe filenames.
 */
final class FileReplayStore implements ReplayStore
{
    public function __construct(private readonly string $directory)
    {
        if (!is_dir($this->directory) && !mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new RuntimeException("Unable to create replay store directory: {$this->directory}");
        }
    }

    public function consume(string $key): bool
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
