<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PHPUnit\Framework\TestCase;
use PayKit\PayCore\Solana\Mints;
use SolanaPhpSdk\Programs\TokenProgram;

final class MintsTest extends TestCase
{
    public function testResolveReturnsNullForNativeSol(): void
    {
        self::assertNull(Mints::resolve('SOL'));
        self::assertNull(Mints::resolve('sol'));
    }

    public function testResolveReturnsKnownSymbolMintsPerNetwork(): void
    {
        self::assertSame('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', Mints::resolve('USDC', 'mainnet-beta'));
        self::assertSame('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', Mints::resolve('USDC', 'devnet'));
        self::assertSame('2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH', Mints::resolve('USDG', 'mainnet-beta'));
        self::assertSame('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo', Mints::resolve('PYUSD', 'mainnet-beta'));
        self::assertSame('CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH', Mints::resolve('CASH', 'mainnet-beta'));
        self::assertSame('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', Mints::resolve('USDT', 'mainnet-beta'));
    }

    public function testResolveCaseInsensitive(): void
    {
        self::assertSame('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', Mints::resolve('usdc'));
        self::assertSame('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', Mints::resolve('UsDc'));
    }

    public function testResolveFallsBackToMainnetForUnknownNetwork(): void
    {
        self::assertSame('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', Mints::resolve('USDT', 'localnet'));
    }

    public function testResolvePassesThroughExistingMintPubkey(): void
    {
        $mint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
        self::assertSame($mint, Mints::resolve($mint, 'devnet'));
    }

    public function testResolveReturnsUnknownSymbolUnchanged(): void
    {
        self::assertSame('FOOBAR', Mints::resolve('FOOBAR'));
    }

    public function testTokenProgramForUsdcIsClassicToken(): void
    {
        self::assertSame(TokenProgram::PROGRAM_ID, Mints::tokenProgramFor('USDC'));
        self::assertSame(TokenProgram::PROGRAM_ID, Mints::tokenProgramFor('USDT', 'mainnet-beta'));
    }

    public function testTokenProgramForToken2022Stablecoins(): void
    {
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, Mints::tokenProgramFor('PYUSD'));
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, Mints::tokenProgramFor('USDG'));
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, Mints::tokenProgramFor('CASH'));
    }

    public function testTokenProgramForUnknownCurrencyFallsBackToClassic(): void
    {
        self::assertSame(TokenProgram::PROGRAM_ID, Mints::tokenProgramFor('FOOBAR'));
    }

    public function testTokenProgramForResolvesMintBack(): void
    {
        $pyusdMint = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo';
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, Mints::tokenProgramFor($pyusdMint));
    }

    public function testSymbolForRoundTripsSymbolsAndMints(): void
    {
        self::assertSame('USDC', Mints::symbolFor('USDC'));
        self::assertSame('USDC', Mints::symbolFor('usdc'));
        self::assertSame('USDC', Mints::symbolFor('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'));
        self::assertSame('CASH', Mints::symbolFor('CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH'));
        self::assertNull(Mints::symbolFor('FOOBAR'));
    }

    // audit #28 — arbitrary mint resolution
    public function testIsKnownMintDistinguishesTableMintsFromArbitrary(): void
    {
        self::assertTrue(Mints::isKnownMint('USDC'));
        self::assertTrue(Mints::isKnownMint('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'));
        // An arbitrary base58 mint address not in the static table.
        self::assertFalse(Mints::isKnownMint('So11111111111111111111111111111111111111112'));
    }

    public function testLooksLikeMintAddress(): void
    {
        self::assertTrue(Mints::looksLikeMintAddress('So11111111111111111111111111111111111111112'));
        self::assertFalse(Mints::looksLikeMintAddress('USDC'));
        self::assertFalse(Mints::looksLikeMintAddress('SOL'));
    }

    public function testResolveTokenProgramOnChainReturnsOwnerForToken2022(): void
    {
        $owner = Mints::resolveTokenProgramOnChain(
            'So11111111111111111111111111111111111111112',
            fn (string $mint): string => TokenProgram::TOKEN_2022_PROGRAM_ID,
        );
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, $owner);
    }

    public function testResolveTokenProgramOnChainRejectsForeignOwner(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Mints::resolveTokenProgramOnChain(
            'So11111111111111111111111111111111111111112',
            fn (string $mint): string => '11111111111111111111111111111111',
        );
    }

    public function testResolveTokenProgramOnChainRejectsMissingMint(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Mints::resolveTokenProgramOnChain(
            'So11111111111111111111111111111111111111112',
            fn (string $mint): ?string => null,
        );
    }

    /**
     * The canonical mainnet slug is `mainnet`. Legacy `mainnet-beta` input
     * is folded back to `mainnet` by normalizeNetwork() inside resolve(),
     * so callers passing either spelling resolve to the same pubkey.
     */
    public function testMainnetBetaAliasResolvesToMainnetForEveryStablecoin(): void
    {
        self::assertSame(
            Mints::resolve('USDC', 'mainnet'),
            Mints::resolve('USDC', 'mainnet-beta')
        );
        self::assertSame(
            Mints::resolve('USDT', 'mainnet'),
            Mints::resolve('USDT', 'mainnet-beta')
        );
        self::assertSame(
            Mints::resolve('USDG', 'mainnet'),
            Mints::resolve('USDG', 'mainnet-beta')
        );
        self::assertSame(
            Mints::resolve('PYUSD', 'mainnet'),
            Mints::resolve('PYUSD', 'mainnet-beta')
        );
        self::assertSame(
            Mints::resolve('CASH', 'mainnet'),
            Mints::resolve('CASH', 'mainnet-beta')
        );
    }
}
