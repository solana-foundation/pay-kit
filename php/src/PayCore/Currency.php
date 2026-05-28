<?php

declare(strict_types=1);

namespace PayKit\PayCore;

/**
 * Fiat denomination a price is quoted in. The wire format uses the
 * uppercase ISO-4217-ish code.
 */
enum Currency: string
{
    case Usd = 'USD';
    case Eur = 'EUR';
    case Gbp = 'GBP';
}
