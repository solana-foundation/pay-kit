<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\PayCore\Currency;
use PayKit\Price;
use PayKit\PayCore\Stablecoin;
use PHPUnit\Framework\TestCase;

final class PriceTest extends TestCase
{
    public function testUsdBuildsBigDecimalAmount(): void
    {
        $p = Price::usd('0.10');
        $this->assertSame(Currency::Usd, $p->currency);
        $this->assertSame('0.10', $p->amountString());
        $this->assertNull($p->primaryCoin());
    }

    public function testUsdWithVariadicSettlement(): void
    {
        $p = Price::usd('1.00', Stablecoin::Usdc, Stablecoin::Usdt);
        $this->assertSame(Stablecoin::Usdc, $p->primaryCoin());
        $this->assertCount(2, $p->settlements);
    }

    public function testEurAndGbpFactories(): void
    {
        $this->assertSame(Currency::Eur, Price::eur('0.50')->currency);
        $this->assertSame(Currency::Gbp, Price::gbp('0.50')->currency);
    }

    public function testPlusRejectsMixedCurrencies(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Price::usd('1.00')->plus(Price::eur('1.00'));
    }

    public function testPlusSumsSameDenom(): void
    {
        $sum = Price::usd('1.00')->plus(Price::usd('2.50'));
        $this->assertSame('3.50', $sum->amountString());
    }

    public function testWithAmount(): void
    {
        $p = Price::usd('1.00', Stablecoin::Usdc);
        $p2 = $p->withAmount('5.00');
        $this->assertSame('5.00', $p2->amountString());
        $this->assertSame(Stablecoin::Usdc, $p2->primaryCoin());
    }

    public function testRejectsInvalidAmount(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Price::usd('not-a-number');
    }
}
