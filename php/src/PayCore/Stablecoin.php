<?php

declare(strict_types=1);

namespace PayKit\PayCore;

/**
 * Stablecoin symbol used as a settlement-asset preference. Backing
 * values are the canonical uppercase tickers that travel on the wire.
 */
enum Stablecoin: string
{
    case Usdc  = 'USDC';
    case Usdt  = 'USDT';
    case Usdg  = 'USDG';
    case Pyusd = 'PYUSD';
    case Cash  = 'CASH';
}
