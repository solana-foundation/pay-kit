<?php

declare(strict_types=1);

namespace PayKit;

/**
 * Fiat denomination a price is quoted in. The wire format uses the
 * uppercase ISO-4217-ish code.
 */
enum Denom: string
{
    case Usd = 'USD';
    case Eur = 'EUR';
    case Gbp = 'GBP';
}
