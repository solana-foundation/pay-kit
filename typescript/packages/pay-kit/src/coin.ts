import type { Price } from './price.js';

/**
 * The settlement coin for a price: its explicit first preference, else the
 * first configured stablecoin, else USDC.
 */
export function resolveCoin(amount: Price, stablecoins: readonly string[]): string {
    return amount.primaryCoin() ?? stablecoins[0] ?? 'USDC';
}
