import { ConfigurationError } from './errors.js';
import type { Price } from './price.js';

/**
 * The settlement coin for a price: its explicit first preference, else the
 * first configured stablecoin, else USDC.
 */
export function resolveCoin(amount: Price, stablecoins: readonly string[]): string {
    return amount.primaryCoin() ?? stablecoins[0] ?? 'USDC';
}

/**
 * The settlement coin for a price together with its on-chain mint.
 *
 * @param toMint - Maps a coin symbol to its mint address on the target network.
 * @param network - Network label used in the error message.
 * @throws {ConfigurationError} when the resolved coin has no mint on the network.
 */
export function resolveCoinAndMint<TMint>(
    amount: Price,
    stablecoins: readonly string[],
    toMint: (coin: string) => TMint | null | undefined,
    network: string,
): { coin: string; mint: TMint } {
    const coin = resolveCoin(amount, stablecoins);
    const mint = toMint(coin);
    if (!mint) throw new ConfigurationError(`No ${coin} mint known for ${network}.`);
    return { coin, mint };
}
