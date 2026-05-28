<?php

declare(strict_types=1);

namespace PayKit\PayCore;

/**
 * Network slug used by Config and Operator. Backing values match the
 * Rust spine's `Network::as_str()` so a wire round-trip is trivial.
 */
enum Network: string
{
    case SolanaMainnet  = 'solana_mainnet';
    case SolanaDevnet   = 'solana_devnet';
    case SolanaLocalnet = 'solana_localnet';

    /**
     * Default public RPC endpoint for this network.
     *
     * Localnet defaults to the hosted Surfpool endpoint (mainnet-state
     * fork) so `new Config(network: Network::SolanaLocalnet)` boots
     * without a local validator. Mirrors Ruby PR #142 + Lua PR #141.
     */
    public function defaultRpcUrl(): string
    {
        return match ($this) {
            self::SolanaMainnet  => 'https://api.mainnet-beta.solana.com',
            self::SolanaDevnet   => 'https://api.devnet.solana.com',
            self::SolanaLocalnet => 'https://402.surfnet.dev:8899',
        };
    }

    /**
     * Network slug accepted by the legacy mints registry. Surfpool
     * clones mainnet state, so localnet resolves to the mainnet row
     * when a stablecoin has no localnet-specific entry.
     */
    public function mintsLabel(): string
    {
        return match ($this) {
            self::SolanaMainnet  => 'mainnet',
            self::SolanaDevnet   => 'devnet',
            self::SolanaLocalnet => 'localnet',
        };
    }

    /**
     * CAIP-2 chain identifier the x402 + MPP accepts entries advertise
     * so clients (like `pay --sandbox curl`) can match the offered
     * network against their active wallet. Surfpool-localnet clones
     * mainnet state, so it reuses the devnet genesis hash by convention
     * (matches the harness fixtures + the rust x402 client).
     */
    public function caip2(): string
    {
        return match ($this) {
            self::SolanaMainnet  => 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
            self::SolanaDevnet,
            self::SolanaLocalnet => 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
        };
    }
}
