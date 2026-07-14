<?php

declare(strict_types=1);

namespace PayKit\Tests\Harness;

use PayKit\Config;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\Protocols\X402\Adapter;
use PayKit\Signer;
use PayKit\Store\ReplayStoreCapability;
use PayKit\Store\Store;
use PayKitHarness\PhpServer\HarnessReplayStore;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 3) . '/harness/php-server/HarnessReplayStore.php';

final class HarnessReplayStoreTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/pay-kit-harness-replay-' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/*') ?: [] as $path) {
            unlink($path);
        }
        if (is_dir($this->directory)) {
            rmdir($this->directory);
        }
    }

    public function testSatisfiesTheExplicitCapabilityAcrossHarnessWorkers(): void
    {
        $store = new HarnessReplayStore($this->directory);

        self::assertInstanceOf(Store::class, $store);
        self::assertInstanceOf(ReplayStoreCapability::class, $store);
        self::assertTrue($store->providesDurableSharedReplayProtection());
        self::assertTrue($store->putIfAbsent('settlement', 'first'));
        self::assertFalse(
            (new HarnessReplayStore($this->directory))->putIfAbsent('settlement', 'second'),
            'a second harness worker must observe the first worker replay marker',
        );

        $script = sprintf(
            'require %s; require %s; $store = new %s(%s); exit($store->putIfAbsent(%s, %s) ? 1 : 0);',
            var_export(dirname(__DIR__, 2) . '/vendor/autoload.php', true),
            var_export(dirname(__DIR__, 3) . '/harness/php-server/HarnessReplayStore.php', true),
            '\\' . HarnessReplayStore::class,
            var_export($this->directory, true),
            var_export('settlement', true),
            var_export('child', true),
        );
        exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($script), $output, $exitCode);
        self::assertSame(0, $exitCode, 'a restarted PHP worker must observe the existing replay marker');

        $signer = Signer::generate();
        $adapter = new Adapter(
            new Config(
                network: Network::SolanaDevnet,
                operator: new Operator(
                    recipient: $signer->pubkey(),
                    signer: $signer,
                    feePayer: true,
                ),
                preflight: false,
            ),
            replayStore: $store,
            recentBlockhashProvider: fn () => null,
        );

        self::assertInstanceOf(Adapter::class, $adapter);
    }
}
