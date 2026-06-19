/** Payment protocols a PayKit server can accept. */
export type Protocol = 'mpp' | 'x402';

/**
 * Canonical PayKit network names, shared across the cross-language SDK family.
 */
export type Network = 'solana_devnet' | 'solana_localnet' | 'solana_mainnet';

/** Solana-style network slugs, accepted anywhere a {@link Network} is. */
export type NetworkSlug = 'devnet' | 'localnet' | 'mainnet-beta' | 'mainnet';

/** Normalizes a canonical network name or Solana slug to the canonical name. */
export function toNetwork(value: Network | NetworkSlug): Network {
    switch (value) {
        case 'devnet':
            return 'solana_devnet';
        case 'localnet':
            return 'solana_localnet';
        case 'mainnet':
        case 'mainnet-beta':
            return 'solana_mainnet';
        default:
            return value;
    }
}

/**
 * Maps a PayKit network name to the Solana network slug used by
 * `@solana/mpp` (`mainnet` / `devnet` / `localnet`).
 */
export function toSolanaNetwork(network: Network): 'devnet' | 'localnet' | 'mainnet' {
    switch (network) {
        case 'solana_devnet':
            return 'devnet';
        case 'solana_localnet':
            return 'localnet';
        case 'solana_mainnet':
            return 'mainnet';
    }
}

/**
 * CAIP-2 chain identifier advertised in `accepts[]` entries.
 *
 * Surfpool-localnet clones mainnet state *including its genesis hash*
 * (`getGenesisHash` returns the mainnet hash `5eykt4…`), so it advertises the
 * mainnet CAIP-2 — that's what a CAIP-2-validating client sees on-chain.
 * Only `devnet` uses the devnet genesis.
 */
export function caip2(network: Network): string {
    return network === 'solana_devnet'
        ? 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'
        : 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
}
