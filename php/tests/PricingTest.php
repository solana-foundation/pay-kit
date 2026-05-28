<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Gate;
use PayKit\Price;
use PayKit\Pricing;
use PHPUnit\Framework\TestCase;

final class PricingTest extends TestCase
{
    public function testReflectionResolvesDeclaredGateProperty(): void
    {
        $pricing = new class () extends Pricing {
            public readonly Gate $report;

            public function __construct()
            {
                $this->report = new Gate(amount: Price::usd('0.10'));
            }
        };
        $g = $pricing->gate('report');
        $this->assertSame('0.10', $g->amount->amountString());
    }

    public function testUnknownGateNameRaises(): void
    {
        $pricing = new class () extends Pricing {};
        $this->expectException(\InvalidArgumentException::class);
        $pricing->gate('nope');
    }

    public function testNonGateValueRaises(): void
    {
        $pricing = new class () extends Pricing {
            public readonly string $reportLabel;
            public function __construct()
            {
                $this->reportLabel = 'not a gate';
            }
        };
        $this->expectException(\InvalidArgumentException::class);
        $pricing->gate('reportLabel');
    }
}
