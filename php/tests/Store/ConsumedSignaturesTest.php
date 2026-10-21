<?php

declare(strict_types=1);

namespace PayKit\Tests\Store;

use PayKit\Store\ConsumedSignatures;
use PayKit\Store\FileStore;
use PayKit\Store\MemoryStore;
use PayKit\Store\Store;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ConsumedSignaturesTest extends TestCase
{
    /**
     * @return iterable<string, array{string, Store}>
     */
    public static function legacyClaims(): iterable
    {
        foreach (['solana-charge:consumed:', 'x402-svm-exact:consumed:'] as $prefix) {
            yield "$prefix memory" => [$prefix, new MemoryStore()];
            $dir = sys_get_temp_dir() . '/pay-kit-ledger-' . bin2hex(random_bytes(6));
            yield "$prefix file" => [$prefix, new FileStore($dir)];
        }
    }

    /**
     * A signature claimed under a pre-ledger MPP or x402 key (by an older
     * replica, or just before an upgrade) stays consumed: it can be neither
     * claimed nor authorized, and the legacy record is only read.
     */
    #[DataProvider('legacyClaims')]
    public function testPreLedgerClaimStaysConsumed(string $prefix, Store $store): void
    {
        $store->putIfAbsent($prefix . 'sig-legacy', true);
        $ledger = new ConsumedSignatures($store);

        self::assertFalse($ledger->claim('sig-legacy'));
        self::assertFalse($ledger->authorize('sig-legacy'));
        self::assertFalse($store->has('solana:consumed-signature:sig-legacy'));
        self::assertFalse($store->has('solana:authorized-signature:sig-legacy'));
        self::assertTrue($store->has($prefix . 'sig-legacy'));

        // Signatures without a legacy record claim and authorize once.
        self::assertTrue($ledger->claim('sig-fresh'));
        self::assertFalse($ledger->claim('sig-fresh'));
        self::assertTrue($ledger->authorize('sig-fresh'));
        self::assertFalse($ledger->authorize('sig-fresh'));
    }

    /**
     * Rolling upgrade: a replica on the previous release claims and checks
     * only its own legacy key. Every claim takes those keys too, so such a
     * replica refuses a payment this release accepted, while this release
     * still authorizes its own claim once.
     */
    #[DataProvider('legacyClaims')]
    public function testClaimIsVisibleToReplicasOnThePreviousRelease(string $prefix, Store $store): void
    {
        $ledger = new ConsumedSignatures($store);

        self::assertTrue($ledger->claim('sig-new'));
        self::assertFalse($store->putIfAbsent($prefix . 'sig-new', true));
        self::assertTrue($ledger->authorize('sig-new'));
        self::assertFalse($ledger->authorize('sig-new'));
    }
}
