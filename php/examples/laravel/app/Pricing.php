<?php

declare(strict_types=1);

namespace App;

use PayKit\Gate;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Pricing as BasePricing;

/**
 * App's pricing catalogue. The `paykit:<name>` route middleware
 * resolves the handle to one of these properties.
 *
 * Demonstrates the dual-protocol surface: `$paid` accepts both x402
 * and MPP; `$x402Only` is locked to x402; `$marketplaceSale` uses
 * fees so x402 auto-disables and only MPP settles.
 */
final class Pricing extends BasePricing
{
    public readonly Gate $paid;
    public readonly Gate $x402Only;
    public readonly Gate $marketplaceSale;

    public function __construct()
    {
        $this->paid = new Gate(
            amount:      Price::usd('0.10'),
            description: 'Premium content',
        );

        $this->x402Only = new Gate(
            amount: Price::usd('0.001'),
            accept: [Protocol::X402],
        );

        // Customer pays $10.00; SELLER nets $9.70; PLATFORM nets $0.30.
        // x402 auto-disabled because fees route to two recipients.
        $this->marketplaceSale = new Gate(
            amount:    Price::usd('10.00'),
            payTo:     'AyNAa2VPe2t5pgg8M61iE6kqMudkV98zsT4rkAZuU6tj',
            feeWithin: ['CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY' => Price::usd('0.30')],
        );
    }
}
