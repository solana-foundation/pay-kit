<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore;

use PayKit\PayCore\Stablecoin;
use PHPUnit\Framework\TestCase;

/**
 * Wire amounts are in atomic units of the settlement coin (RULINGS C2/X2),
 * so the adapters scale prices by Stablecoin::decimals() rather than a
 * constant. Every supported stablecoin mint has 6 decimals on-chain.
 */
final class StablecoinTest extends TestCase
{
    public function testEveryStablecoinStatesItsMintDecimals(): void
    {
        foreach (Stablecoin::cases() as $coin) {
            $this->assertSame(6, $coin->decimals(), $coin->value);
        }
    }
}
