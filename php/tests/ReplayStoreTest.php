<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;
use SolanaMpp\Server\FileReplayStore;
use SolanaMpp\Server\MemoryReplayStore;

final class ReplayStoreTest extends TestCase
{
    public function testMemoryStoreRejectsDuplicate(): void
    {
        $store = new MemoryReplayStore();

        self::assertTrue($store->consume('k1'));
        self::assertFalse($store->consume('k1'));
        self::assertTrue($store->consume('k2'));
    }

    public function testFileStoreRejectsDuplicateAcrossInstances(): void
    {
        $directory = sys_get_temp_dir() . '/mpp-file-replay-' . bin2hex(random_bytes(6));
        $first = new FileReplayStore($directory);
        $second = new FileReplayStore($directory);

        try {
            self::assertTrue($first->consume('solana-charge:consumed:sig'));
            self::assertFalse($second->consume('solana-charge:consumed:sig'));
            self::assertTrue($second->consume('solana-charge:consumed:other'));
        } finally {
            $this->removeDirectory($directory);
        }
    }

    public function testFileStoreCreatesNestedDirectory(): void
    {
        $directory = sys_get_temp_dir() . '/mpp-file-replay-nested-' . bin2hex(random_bytes(6)) . '/a/b';
        $store = new FileReplayStore($directory);
        try {
            self::assertTrue($store->consume('k1'));
            self::assertDirectoryExists($directory);
        } finally {
            $this->removeDirectory(dirname($directory, 2));
        }
    }

    private function removeDirectory(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }
        $items = scandir($path);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $full = $path . DIRECTORY_SEPARATOR . $item;
            if (is_dir($full)) {
                $this->removeDirectory($full);
            } else {
                @unlink($full);
            }
        }
        @rmdir($path);
    }
}
