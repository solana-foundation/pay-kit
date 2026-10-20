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

    /**
     * On-chain decimals of the coin's mint. Wire amounts are in atomic
     * units of the asset (RULINGS C2/X2), so every price is scaled by this,
     * never by an assumed constant. A new case must state its own.
     */
    public function decimals(): int
    {
        return match ($this) {
            self::Usdc, self::Usdt, self::Usdg, self::Pyusd, self::Cash => 6,
        };
    }
}
