<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SolanaMpp\X402\Interop\Mints;

require_once __DIR__ . '/../src/x402/InteropServer.php';

use function SolanaMpp\X402\Interop\token_program_for_mint;
use function SolanaMpp\X402\Interop\mint_uses_token_2022;

use const SolanaMpp\X402\Interop\DEFAULT_TOKEN_PROGRAM;
use const SolanaMpp\X402\Interop\TOKEN_2022_PROGRAM;

/**
 * Regression coverage for `token_program_for_mint()` parity with the Rust
 * spine table in `rust/crates/x402/src/protocol/schemes/exact/types.rs`
 * (`stablecoin_uses_token_2022` + `default_token_program_for_currency`).
 *
 * The prior implementation special-cased only `PYUSD_DEVNET`, which silently
 * advertised the wrong token program for USDG, CASH, and PYUSD mainnet /
 * testnet paths and broke honest payments for those accepted currencies.
 */
final class X402InteropTokenProgramTest extends TestCase
{
    /**
     * @return array<string, array{0: string}>
     */
    public static function token2022MintsProvider(): array
    {
        return [
            'USDG mainnet' => [Mints::USDG_MAINNET],
            'USDG devnet' => [Mints::USDG_DEVNET],
            'USDG testnet (alias of devnet)' => [Mints::USDG_TESTNET],
            'PYUSD mainnet' => [Mints::PYUSD_MAINNET],
            'PYUSD devnet' => [Mints::PYUSD_DEVNET],
            'PYUSD testnet (alias of devnet)' => [Mints::PYUSD_TESTNET],
            'CASH mainnet' => [Mints::CASH_MAINNET],
        ];
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function legacyTokenProgramMintsProvider(): array
    {
        return [
            'USDC mainnet' => [Mints::USDC_MAINNET],
            'USDC devnet' => [Mints::USDC_DEVNET],
            'USDC testnet (alias of devnet)' => [Mints::USDC_TESTNET],
            'USDT mainnet' => [Mints::USDT_MAINNET],
            'unknown mint passes through to legacy' => ['SoMeOtHeRMiNtThAtIsNotKnown1234567890ABCDEFG'],
        ];
    }

    #[DataProvider('token2022MintsProvider')]
    public function testToken2022MintsResolveToToken2022Program(string $mint): void
    {
        self::assertTrue(
            mint_uses_token_2022($mint),
            sprintf('expected %s to be a Token-2022 mint', $mint),
        );
        self::assertSame(TOKEN_2022_PROGRAM, token_program_for_mint($mint));
    }

    #[DataProvider('legacyTokenProgramMintsProvider')]
    public function testLegacyTokenProgramMintsResolveToClassicProgram(string $mint): void
    {
        self::assertFalse(
            mint_uses_token_2022($mint),
            sprintf('expected %s NOT to be a Token-2022 mint', $mint),
        );
        self::assertSame(DEFAULT_TOKEN_PROGRAM, token_program_for_mint($mint));
    }
}
