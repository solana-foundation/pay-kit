<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;
use SolanaMpp\Common\StablecoinMints;
use SolanaPhpSdk\Programs\TokenProgram;

final class StablecoinMintsTest extends TestCase
{
    public function testResolveReturnsNullForNativeSol(): void
    {
        self::assertNull(StablecoinMints::resolve('SOL'));
        self::assertNull(StablecoinMints::resolve('sol'));
    }

    public function testResolveReturnsKnownSymbolMintsPerNetwork(): void
    {
        self::assertSame('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', StablecoinMints::resolve('USDC', 'mainnet-beta'));
        self::assertSame('4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU', StablecoinMints::resolve('USDC', 'devnet'));
        self::assertSame('2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH', StablecoinMints::resolve('USDG', 'mainnet-beta'));
        self::assertSame('2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo', StablecoinMints::resolve('PYUSD', 'mainnet-beta'));
        self::assertSame('CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH', StablecoinMints::resolve('CASH', 'mainnet-beta'));
        self::assertSame('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', StablecoinMints::resolve('USDT', 'mainnet-beta'));
    }

    public function testResolveCaseInsensitive(): void
    {
        self::assertSame('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', StablecoinMints::resolve('usdc'));
        self::assertSame('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', StablecoinMints::resolve('UsDc'));
    }

    public function testResolveFallsBackToMainnetForUnknownNetwork(): void
    {
        self::assertSame('Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB', StablecoinMints::resolve('USDT', 'localnet'));
    }

    public function testResolvePassesThroughExistingMintPubkey(): void
    {
        $mint = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
        self::assertSame($mint, StablecoinMints::resolve($mint, 'devnet'));
    }

    public function testResolveReturnsUnknownSymbolUnchanged(): void
    {
        self::assertSame('FOOBAR', StablecoinMints::resolve('FOOBAR'));
    }

    public function testTokenProgramForUsdcIsClassicToken(): void
    {
        self::assertSame(TokenProgram::PROGRAM_ID, StablecoinMints::tokenProgramFor('USDC'));
        self::assertSame(TokenProgram::PROGRAM_ID, StablecoinMints::tokenProgramFor('USDT', 'mainnet-beta'));
    }

    public function testTokenProgramForToken2022Stablecoins(): void
    {
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, StablecoinMints::tokenProgramFor('PYUSD'));
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, StablecoinMints::tokenProgramFor('USDG'));
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, StablecoinMints::tokenProgramFor('CASH'));
    }

    public function testTokenProgramForUnknownCurrencyFallsBackToClassic(): void
    {
        self::assertSame(TokenProgram::PROGRAM_ID, StablecoinMints::tokenProgramFor('FOOBAR'));
    }

    public function testTokenProgramForResolvesMintBack(): void
    {
        $pyusdMint = '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo';
        self::assertSame(TokenProgram::TOKEN_2022_PROGRAM_ID, StablecoinMints::tokenProgramFor($pyusdMint));
    }

    public function testSymbolForRoundTripsSymbolsAndMints(): void
    {
        self::assertSame('USDC', StablecoinMints::symbolFor('USDC'));
        self::assertSame('USDC', StablecoinMints::symbolFor('usdc'));
        self::assertSame('USDC', StablecoinMints::symbolFor('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'));
        self::assertSame('CASH', StablecoinMints::symbolFor('CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH'));
        self::assertNull(StablecoinMints::symbolFor('FOOBAR'));
    }

    /**
     * The canonical mainnet slug is `mainnet`. The legacy `mainnet-beta`
     * spelling is exposed as an aliased key for backward compatibility.
     * This test catches alias drift: if a future commit changes the
     * pubkey for one spelling but forgets the other, downstream consumers
     * doing raw bracket access on either key get inconsistent results.
     */
    public function testMainnetBetaAliasMatchesMainnetForEveryStablecoin(): void
    {
        self::assertSame(StablecoinMints::USDC['mainnet'], StablecoinMints::USDC['mainnet-beta']);
        self::assertSame(StablecoinMints::USDT['mainnet'], StablecoinMints::USDT['mainnet-beta']);
        self::assertSame(StablecoinMints::USDG['mainnet'], StablecoinMints::USDG['mainnet-beta']);
        self::assertSame(StablecoinMints::PYUSD['mainnet'], StablecoinMints::PYUSD['mainnet-beta']);
        self::assertSame(StablecoinMints::CASH['mainnet'], StablecoinMints::CASH['mainnet-beta']);
    }
}
