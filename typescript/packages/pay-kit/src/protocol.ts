/** Payment protocols a PayKit server can accept. */
export type Protocol = 'mpp' | 'x402';

/**
 * Canonical PayKit network names, shared across the cross-language SDK family.
 */
export type Network = 'solana_devnet' | 'solana_localnet' | 'solana_mainnet';

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
 * Surfpool-localnet clones mainnet state but reuses the devnet genesis hash
 * by convention, matching the harness fixtures and the other PayKit SDKs.
 */
export function caip2(network: Network): string {
    return network === 'solana_mainnet'
        ? 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
        : 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
}
