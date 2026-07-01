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
 * Assert that a coin resolved to a mint on the target network.
 *
 * @param coin - The settlement coin symbol.
 * @param mint - The mint resolved for the coin, if any.
 * @param network - Network label used in the error message.
 * @throws {ConfigurationError} when the coin has no mint on the network.
 */
export function requireMint(coin: string, mint: string | undefined, network: string): string {
    if (!mint) throw new ConfigurationError(`No ${coin} mint known for ${network}.`);
    return mint;
}
