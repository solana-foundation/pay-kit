<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Exception\MixedCurrenciesException;
use PayKit\Exception\ProtocolIncompatibleException;
use PayKit\Gate;
use PayKit\Price;
use PayKit\Protocol;
use PHPUnit\Framework\TestCase;

final class GateTest extends TestCase
{
    public function testSimpleGateNoFees(): void
    {
        $g = new Gate(amount: Price::usd('0.10'));
        $this->assertSame('0.10', $g->total()->amountString());
        $this->assertFalse($g->hasFees());
    }

    public function testFeeWithinNetsPayToDown(): void
    {
        $g = new Gate(
            amount: Price::usd('10.00'),
            payTo: 'SELLER',
            feeWithin: ['PLATFORM' => Price::usd('0.30')],
        );
        $this->assertTrue($g->hasFees());
        $this->assertSame('10.00', $g->total()->amountString()); // customer pays amount
        $this->assertSame('9.70', $g->payout('SELLER')->amountString());
        $this->assertSame('0.30', $g->payout('PLATFORM')->amountString());
    }

    public function testFeeOnTopAddsToTotal(): void
    {
        $g = new Gate(
            amount: Price::usd('10.00'),
            payTo: 'SELLER',
            feeOnTop: ['PLATFORM' => Price::usd('0.50')],
        );
        $this->assertSame('10.50', $g->total()->amountString());
        $this->assertSame('10.00', $g->payout('SELLER')->amountString());
    }

    public function testMixedCurrenciesRejected(): void
    {
        $this->expectException(MixedCurrenciesException::class);
        new Gate(
            amount: Price::usd('1.00'),
            payTo: 'SELLER',
            feeWithin: ['PLATFORM' => Price::eur('0.10')],
        );
    }

    public function testSumFeeWithinExceedingAmountRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Gate(
            amount: Price::usd('1.00'),
            payTo: 'SELLER',
            feeWithin: ['PLATFORM' => Price::usd('2.00')],
        );
    }

    public function testExplicitX402AcceptOnFeeGateRejected(): void
    {
        $this->expectException(ProtocolIncompatibleException::class);
        new Gate(
            amount: Price::usd('1.00'),
            payTo: 'SELLER',
            accept: [Protocol::X402],
            feeWithin: ['PLATFORM' => Price::usd('0.10')],
        );
    }

    public function testPayoutNullForUnaddressedRecipient(): void
    {
        $g = new Gate(amount: Price::usd('1.00'), payTo: 'SELLER');
        $this->assertNull($g->payout('STRANGER'));
    }
}
