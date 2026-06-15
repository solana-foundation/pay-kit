export const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
export const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
export const ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const SYSTEM_PROGRAM = '11111111111111111111111111111111';
export const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
export const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

/** Canonical subscriptions program ID. */
export const SUBSCRIPTIONS_PROGRAM = 'De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44';

/** subscriptions program instruction discriminators (single byte). */
export const SUBSCRIPTIONS_INIT_AUTHORITY_DISCRIMINATOR = 0;
export const SUBSCRIPTIONS_TRANSFER_DISCRIMINATOR = 10;
export const SUBSCRIPTIONS_SUBSCRIBE_DISCRIMINATOR = 11;
export const SUBSCRIPTIONS_CANCEL_DISCRIMINATOR = 12;

// The canonical mainnet slug is `mainnet`. The legacy `mainnet-beta`
// spelling is kept as an aliased key so direct bracket access from
// consumer code (e.g. USDC['mainnet-beta']) keeps working through the
// transition. Internal lookups go through normalizeNetwork below.
export const USDC: Record<string, string> = {
    devnet: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    mainnet: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    'mainnet-beta': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
};

export const USDT: Record<string, string> = {
    mainnet: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
    'mainnet-beta': 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
};

export const USDG: Record<string, string> = {
    devnet: '4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7',
    mainnet: '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH',
    'mainnet-beta': '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH',
};

export const PYUSD: Record<string, string> = {
    devnet: 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM',
    mainnet: '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo',
    'mainnet-beta': '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo',
};

export const CASH: Record<string, string> = {
    mainnet: 'CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH',
    'mainnet-beta': 'CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH',
};

export const STABLECOIN_MINTS = {
    CASH,
    PYUSD,
    USDC,
    USDG,
    USDT,
} as const;

export type StablecoinSymbol = keyof typeof STABLECOIN_MINTS;

export const STABLECOIN_TOKEN_PROGRAMS: Record<StablecoinSymbol, string> = {
    CASH: TOKEN_2022_PROGRAM,
    PYUSD: TOKEN_2022_PROGRAM,
    USDC: TOKEN_PROGRAM,
    USDG: TOKEN_2022_PROGRAM,
    USDT: TOKEN_PROGRAM,
};

export const DEFAULT_RPC_URLS: Record<string, string> = {
    devnet: 'https://api.devnet.solana.com',
    localnet: 'http://localhost:8899',
    mainnet: 'https://api.mainnet-beta.solana.com',
    'mainnet-beta': 'https://api.mainnet-beta.solana.com',
};

/**
 * Maintainer canonical for the mainnet slug is `mainnet`. The legacy
 * `mainnet-beta` spelling is accepted as a backward-compatible alias
 * and normalized to `mainnet`. Other networks pass through unchanged.
 * Exposed so client helpers can compare and look up consistently.
 */
export function normalizeNetwork(network: string): string {
    const lower = network.toLowerCase();
    if (lower === 'mainnet' || lower === 'mainnet-beta') {
        return 'mainnet';
    }
    return network;
}

/**
 * Canonical network slug is `mainnet`. The legacy `mainnet-beta` spelling is
 * accepted as a backward-compatible alias (normalized to `mainnet`).
 *
 * Per the spec, the network MUST be one of mainnet / devnet / localnet.
 * Anything else (`testnet`, typos, empty string) is rejected at boot rather
 * than silently treated as mainnet.
 */
export const CANONICAL_NETWORKS = ['mainnet', 'devnet', 'localnet'] as const;

/**
 * Validates a network slug against the allowlist, throwing on anything outside
 * {mainnet, devnet, localnet} (or the `mainnet-beta` alias). Use at server boot
 * so misconfigured networks fail fast instead of silently defaulting to mainnet.
 */
export function validateNetwork(network: string): void {
    if (network.length === 0) {
        throw new Error('network must not be empty (expected one of: mainnet, devnet, localnet)');
    }
    const normalized = normalizeNetwork(network);
    if (!(CANONICAL_NETWORKS as readonly string[]).includes(normalized)) {
        throw new Error(`Unsupported network "${network}" (expected one of: mainnet, devnet, localnet)`);
    }
}

export function resolveStablecoinMint(currency: string, network = 'mainnet'): string | undefined {
    const key = normalizeNetwork(network);
    switch (currency.toUpperCase()) {
        case 'SOL':
            return undefined;
        case 'USDC':
            return USDC[key] ?? USDC.mainnet;
        case 'USDT':
            return USDT[key] ?? USDT.mainnet;
        case 'USDG':
            return USDG[key] ?? USDG.mainnet;
        case 'PYUSD':
            return PYUSD[key] ?? PYUSD.mainnet;
        case 'CASH':
            return CASH[key] ?? CASH.mainnet;
        default:
            return currency;
    }
}

export function defaultTokenProgramForCurrency(currency: string | undefined, network = 'mainnet'): string {
    const symbol = currency
        ? stablecoinSymbolForCurrency(resolveStablecoinMint(currency, network) ?? currency)
        : undefined;
    return symbol ? STABLECOIN_TOKEN_PROGRAMS[symbol] : TOKEN_PROGRAM;
}

export function stablecoinSymbolForCurrency(currency: string): StablecoinSymbol | undefined {
    const normalized = currency.toUpperCase();
    if (normalized in STABLECOIN_MINTS) return normalized as StablecoinSymbol;

    for (const [symbol, mints] of Object.entries(STABLECOIN_MINTS)) {
        if (Object.values(mints).includes(currency)) return symbol as StablecoinSymbol;
    }
}
