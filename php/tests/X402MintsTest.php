<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;
use SolanaMpp\X402\Interop\Mints;

/**
 * Verifies the x402 `Mints` table mirrors the Rust spine
 * (`rust/crates/x402/src/protocol/schemes/exact/types.rs::mints`)
 * byte-for-byte, and that resolution is fail-closed — no silent
 * mainnet fallback for declared symbols on undeclared networks.
 */
final class X402MintsTest extends TestCase
{
    public function testUsdcConstantsMatchSpine(): void
    {
        self::assertSame('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', Mints::USDC_MAINNET);
        self::assertSame('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', Mints::USDC_DEVNET);
        self::assertSame(Mints::USDC_DEVNET, Mints::USDC_TESTNET);
    }

    public function testUsdtMainnetMatchesSpine(): void
    {
        self::assertSame('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', Mints::USDT_MAINNET);
    }

    public function testUsdgConstantsMatchSpine(): void
    {
        self::assertSame('2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH', Mints::USDG_MAINNET);
        self::assertSame('4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7', Mints::USDG_DEVNET);
        self::assertSame(Mints::USDG_DEVNET, Mints::USDG_TESTNET);
    }

    public function testPyusdConstantsMatchSpine(): void
    {
        self::assertSame('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo', Mints::PYUSD_MAINNET);
        self::assertSame('CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM', Mints::PYUSD_DEVNET);
        self::assertSame(Mints::PYUSD_DEVNET, Mints::PYUSD_TESTNET);
    }

    public function testCashMainnetMatchesSpine(): void
    {
        self::assertSame('CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH', Mints::CASH_MAINNET);
    }

    public function testResolveHappyPathPerNetwork(): void
    {
        self::assertSame(Mints::USDC_MAINNET, Mints::resolve('USDC', 'mainnet'));
        self::assertSame(Mints::USDC_DEVNET, Mints::resolve('USDC', 'devnet'));
        self::assertSame(Mints::USDC_TESTNET, Mints::resolve('USDC', 'testnet'));

        self::assertSame(Mints::USDT_MAINNET, Mints::resolve('USDT', 'mainnet'));

        self::assertSame(Mints::USDG_MAINNET, Mints::resolve('USDG', 'mainnet'));
        self::assertSame(Mints::USDG_DEVNET, Mints::resolve('USDG', 'devnet'));
        self::assertSame(Mints::USDG_TESTNET, Mints::resolve('USDG', 'testnet'));

        self::assertSame(Mints::PYUSD_MAINNET, Mints::resolve('PYUSD', 'mainnet'));
        self::assertSame(Mints::PYUSD_DEVNET, Mints::resolve('PYUSD', 'devnet'));
        self::assertSame(Mints::PYUSD_TESTNET, Mints::resolve('PYUSD', 'testnet'));

        self::assertSame(Mints::CASH_MAINNET, Mints::resolve('CASH', 'mainnet'));
    }

    public function testResolveCaseInsensitiveSymbol(): void
    {
        self::assertSame(Mints::USDC_MAINNET, Mints::resolve('usdc', 'mainnet'));
        self::assertSame(Mints::PYUSD_DEVNET, Mints::resolve('PyUsD', 'devnet'));
    }

    public function testResolveNetworkAliases(): void
    {
        // mainnet-beta -> mainnet
        self::assertSame(Mints::USDC_MAINNET, Mints::resolve('USDC', 'mainnet-beta'));
        // localnet -> devnet (matches spine's resolve_stablecoin_mint)
        self::assertSame(Mints::USDC_DEVNET, Mints::resolve('USDC', 'localnet'));
    }

    /**
     * Fail-closed for declared symbols on undeclared networks. USDT/CASH
     * only have a mainnet entry in spine; spine's resolver falls back to
     * mainnet for any cluster, but the canonical `mints` table itself
     * does not declare those entries. The Mints lookup must NOT invent
     * mappings spine doesn't have.
     */
    public function testResolveReturnsNullForUndeclaredNetwork(): void
    {
        self::assertNull(Mints::resolve('USDT', 'devnet'));
        self::assertNull(Mints::resolve('USDT', 'testnet'));
        self::assertNull(Mints::resolve('USDT', 'localnet'));
        self::assertNull(Mints::resolve('CASH', 'devnet'));
        self::assertNull(Mints::resolve('CASH', 'testnet'));
    }

    public function testResolveReturnsNullForUnknownSymbol(): void
    {
        self::assertNull(Mints::resolve('FOOBAR', 'mainnet'));
        self::assertNull(Mints::resolve('SOL', 'mainnet'));
        self::assertNull(Mints::resolve('', 'mainnet'));
    }

    public function testResolveReturnsNullForUnknownNetwork(): void
    {
        self::assertNull(Mints::resolve('USDC', 'arbitrum'));
        self::assertNull(Mints::resolve('USDC', ''));
    }
}
