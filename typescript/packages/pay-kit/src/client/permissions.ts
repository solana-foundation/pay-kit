import { address } from '@solana/kit';
import { resolveStablecoinMint, stablecoinSymbolForCurrency } from '@solana/mpp/client';

/** Solana cluster slugs used by PayKit's public client API. */
export type SolanaNetwork = 'devnet' | 'localnet' | 'mainnet';

const NETWORKS = new Set<SolanaNetwork>(['mainnet', 'devnet', 'localnet']);
const MICRO_USD = 1_000_000n;

/** A positive USD amount represented exactly in integer micro-dollars. */
export class UsdAmount {
    readonly microUsd: bigint;

    private constructor(microUsd: bigint) {
        this.microUsd = microUsd;
    }

    /**
     * Parses a positive USD amount with at most six fractional digits.
     *
     * @param value - Decimal USD value, optionally prefixed with `$`.
     * @returns An integer-backed USD amount.
     * @throws {PermissionConfigurationError} When the value is malformed, zero, or too precise.
     */
    static parse(value: string): UsdAmount {
        const normalized = value.startsWith('$') ? value.slice(1) : value;
        const match = /^(\d+)(?:\.(\d{0,6}))?$/.exec(normalized);
        if (!match) throw new PermissionConfigurationError(`Invalid USD amount: ${JSON.stringify(value)}`);
        const fraction = (match[2] ?? '').padEnd(6, '0');
        const microUsd = BigInt(match[1]) * MICRO_USD + BigInt(fraction || '0');
        if (microUsd <= 0n) throw new PermissionConfigurationError('USD limits must be greater than zero');
        return new UsdAmount(microUsd);
    }
}

/**
 * Parses a USD permission cap.
 *
 * @param value - Decimal USD value, optionally prefixed with `$`.
 * @returns An integer-backed USD amount.
 */
export function usd(value: string): UsdAmount {
    return UsdAmount.parse(value);
}

/** One explicitly permitted SPL asset and its optional atomic cap. */
export class AssetPermission {
    readonly maxAmountPerPayment: bigint | undefined;
    readonly mint: string;
    readonly network: SolanaNetwork;

    private constructor(network: SolanaNetwork, mint: string, maxAmountPerPayment?: bigint) {
        this.network = network;
        this.mint = mint;
        this.maxAmountPerPayment = maxAmountPerPayment;
    }

    /** Allow one symbol or mint without an atomic cap. */
    static allow(network: SolanaNetwork, asset: string): AssetPermission {
        return new AssetPermission(assertNetwork(network), normalizeMint(network, asset));
    }

    /** Allow one symbol or mint with an atomic per-payment cap. */
    static withCap(network: SolanaNetwork, asset: string, cap: bigint): AssetPermission {
        if (cap <= 0n) throw new PermissionConfigurationError('Atomic caps must be greater than zero');
        return new AssetPermission(assertNetwork(network), normalizeMint(network, asset), cap);
    }
}

/** An exact-origin cap override. The origin must still pass the global allowlist. */
export class OriginPermissionOverride {
    readonly assetCaps: readonly AssetPermission[];
    readonly maxAmountPerPayment: UsdAmount | false | undefined;
    readonly origin: string;

    /** Create an immutable exact-origin override. Prefer {@link OriginPermissionOverride.builder}. */
    constructor(
        origin: string,
        maxAmountPerPayment: UsdAmount | false | undefined,
        assetCaps: readonly AssetPermission[],
    ) {
        this.origin = normalizeOrigin(origin);
        this.maxAmountPerPayment = maxAmountPerPayment;
        this.assetCaps = assetCaps;
    }

    /** Start an override for one HTTP(S) origin. */
    static builder(origin: string): OriginPermissionOverrideBuilder {
        return new OriginPermissionOverrideBuilder(origin);
    }
}

/** Fluent builder for {@link OriginPermissionOverride}. */
export class OriginPermissionOverrideBuilder {
    readonly #assetCaps: AssetPermission[] = [];
    readonly #origin: string;
    #maxAmountPerPayment: UsdAmount | false | undefined;

    constructor(origin: string) {
        this.#origin = normalizeOrigin(origin);
    }

    /** Replace the global stablecoin cap at this origin. */
    maxAmountPerPayment(cap: UsdAmount): this {
        this.#maxAmountPerPayment = cap;
        return this;
    }

    /** Remove the stablecoin cap at this origin. */
    withoutAmountCap(): this {
        this.#maxAmountPerPayment = false;
        return this;
    }

    /** Replace an asset's global atomic cap at this origin. */
    assetCap(permission: AssetPermission): this {
        this.#assetCaps.push(permission);
        return this;
    }

    /** Build the immutable origin override. */
    build(): OriginPermissionOverride {
        return new OriginPermissionOverride(
            this.#origin,
            this.#maxAmountPerPayment,
            Object.freeze([...this.#assetCaps]),
        );
    }
}

/** A normalized payment offer evaluated before transaction construction. */
export type PaymentCandidate = {
    readonly amount: bigint;
    readonly mint: string;
    readonly network: SolanaNetwork;
    readonly origin: string;
};

/** Stable reason codes for permission denials. */
export type PermissionDeniedCode =
    | 'amount_exceeds_limit'
    | 'asset_not_allowed'
    | 'invalid_challenge_terms'
    | 'network_not_allowed'
    | 'origin_not_allowed';

/** One rejected payment option. */
export type PermissionRejection = {
    readonly actual?: bigint;
    readonly code: PermissionDeniedCode;
    readonly limit?: bigint;
    readonly message: string;
};

/** No advertised payment option passed the configured permissions. */
export class PermissionDeniedError extends Error {
    override readonly name = 'PermissionDeniedError';

    constructor(readonly rejections: readonly PermissionRejection[]) {
        super('No server payment challenge is permitted');
    }
}

/** Invalid client permission configuration. */
export class PermissionConfigurationError extends Error {
    override readonly name = 'PermissionConfigurationError';
}

/** Result of authorizing one immutable payment candidate. */
export type AuthorizedPayment = {
    readonly maxAmountAtomic: bigint | undefined;
};

/**
 * Protocol-neutral permissions checked before PayKit builds or signs a payment.
 *
 * The default permits known stablecoins on mainnet up to USD 1.00 from any
 * HTTP(S) origin. Caps resolve in this order: origin asset, origin stablecoin,
 * global asset, then global stablecoin.
 */
export class ClientPermissions {
    readonly #allowAnyAsset: boolean;
    readonly #allowedAssets: readonly AssetPermission[];
    readonly #allowedNetworks: ReadonlySet<SolanaNetwork>;
    readonly #allowedOrigins: ReadonlySet<string> | undefined;
    readonly #maxAmountPerPayment: UsdAmount | undefined;
    readonly #originOverrides: ReadonlyMap<string, OriginPermissionOverride>;

    /** Create an immutable policy snapshot. Prefer {@link ClientPermissions.builder}. */
    constructor(options: {
        allowAnyAsset: boolean;
        allowedAssets: readonly AssetPermission[];
        allowedNetworks: ReadonlySet<SolanaNetwork>;
        allowedOrigins: ReadonlySet<string> | undefined;
        maxAmountPerPayment: UsdAmount | undefined;
        originOverrides: ReadonlyMap<string, OriginPermissionOverride>;
    }) {
        this.#allowAnyAsset = options.allowAnyAsset;
        this.#allowedAssets = options.allowedAssets;
        this.#allowedNetworks = options.allowedNetworks;
        this.#allowedOrigins = options.allowedOrigins;
        this.#maxAmountPerPayment = options.maxAmountPerPayment;
        this.#originOverrides = options.originOverrides;
    }

    /** Start with any origin, mainnet, known stablecoins, and a USD 1.00 cap. */
    static builder(): ClientPermissionsBuilder {
        return new ClientPermissionsBuilder();
    }

    /** Permit every payment type supported by the high-level client. */
    static unrestricted(): ClientPermissions {
        return new ClientPermissions({
            allowAnyAsset: true,
            allowedAssets: [],
            allowedNetworks: new Set(),
            allowedOrigins: undefined,
            maxAmountPerPayment: undefined,
            originOverrides: new Map(),
        });
    }

    /**
     * Evaluate one normalized offer.
     *
     * @param candidate - Immutable terms derived from the server challenge and response URL.
     * @returns The resolved atomic cap for defense-in-depth protocol checks.
     * @throws {PermissionDeniedError} When the candidate is outside the policy.
     */
    authorize(candidate: PaymentCandidate): AuthorizedPayment {
        const origin = normalizeOrigin(candidate.origin);
        if (this.#allowedOrigins && !this.#allowedOrigins.has(origin)) {
            throw denial('origin_not_allowed', `Origin ${origin} is not allowed`);
        }
        if (this.#allowedNetworks.size > 0 && !this.#allowedNetworks.has(candidate.network)) {
            throw denial('network_not_allowed', `Network ${candidate.network} is not allowed`);
        }
        if (candidate.amount < 0n) {
            throw denial('invalid_challenge_terms', 'Challenge amount is not a non-negative integer');
        }

        let mint: string;
        try {
            mint = normalizeMint(candidate.network, candidate.mint);
        } catch (error) {
            if (!(error instanceof PermissionConfigurationError)) throw error;
            throw denial('invalid_challenge_terms', error.message);
        }
        const globalAsset = this.#allowedAssets.find(entry => matchesAsset(entry, candidate.network, mint));
        const knownAsset = stablecoinSymbolForCurrency(mint) !== undefined;
        if (!knownAsset && !this.#allowAnyAsset && !globalAsset) {
            throw denial('asset_not_allowed', `Asset ${mint} is not allowed on ${candidate.network}`);
        }

        const originOverride = this.#originOverrides.get(origin);
        const originAsset = originOverride?.assetCaps.find(entry => matchesAsset(entry, candidate.network, mint));
        let cap: bigint | undefined;
        if (originAsset?.maxAmountPerPayment !== undefined) {
            cap = originAsset.maxAmountPerPayment;
        } else if (knownAsset && originOverride?.maxAmountPerPayment !== undefined) {
            cap =
                originOverride.maxAmountPerPayment === false ? undefined : originOverride.maxAmountPerPayment.microUsd;
        } else if (globalAsset?.maxAmountPerPayment !== undefined) {
            cap = globalAsset.maxAmountPerPayment;
        } else if (knownAsset) {
            cap = this.#maxAmountPerPayment?.microUsd;
        }

        if (cap !== undefined && candidate.amount > cap) {
            throw new PermissionDeniedError([
                {
                    actual: candidate.amount,
                    code: 'amount_exceeds_limit',
                    limit: cap,
                    message: `Payment amount ${candidate.amount} exceeds cap ${cap} for ${origin}`,
                },
            ]);
        }
        return { maxAmountAtomic: cap };
    }
}

/** Fluent builder for {@link ClientPermissions}. */
export class ClientPermissionsBuilder {
    #allowAnyAsset = false;
    readonly #allowedAssets: AssetPermission[] = [];
    #allowedNetworks = new Set<SolanaNetwork>(['mainnet']);
    #allowedOrigins: Set<string> | undefined;
    #maxAmountPerPayment: UsdAmount | undefined = usd('1');
    readonly #originOverrides = new Map<string, OriginPermissionOverride>();

    /** Restrict payments to an exact origin. The first call creates an allowlist. */
    allowOrigin(origin: string): this {
        (this.#allowedOrigins ??= new Set()).add(normalizeOrigin(origin));
        return this;
    }

    /** Permit challenges from any HTTP(S) origin. */
    allowAnyOrigin(): this {
        this.#allowedOrigins = undefined;
        return this;
    }

    /** Add a permitted Solana cluster. */
    allowNetwork(network: SolanaNetwork): this {
        this.#allowedNetworks.add(assertNetwork(network));
        return this;
    }

    /** Replace the default network set with one Solana cluster. */
    onlyNetwork(network: SolanaNetwork): this {
        this.#allowedNetworks = new Set([assertNetwork(network)]);
        return this;
    }

    /** Set the global per-payment cap for known stablecoins. */
    maxAmountPerPayment(cap: UsdAmount): this {
        this.#maxAmountPerPayment = cap;
        return this;
    }

    /** Remove the global stablecoin cap. */
    withoutAmountCap(): this {
        this.#maxAmountPerPayment = undefined;
        return this;
    }

    /** Permit every SPL mint. Unknown assets remain uncapped unless listed. */
    allowAnyAsset(): this {
        this.#allowAnyAsset = true;
        return this;
    }

    /** Add one permitted asset and optional atomic cap. */
    allowAsset(permission: AssetPermission): this {
        this.#allowedAssets.push(permission);
        return this;
    }

    /** Add an exact-origin cap override. This does not grant the origin. */
    overrideOrigin(permission: OriginPermissionOverride): this {
        this.#originOverrides.set(permission.origin, permission);
        return this;
    }

    /** Build an immutable permission policy. */
    build(): ClientPermissions {
        return new ClientPermissions({
            allowAnyAsset: this.#allowAnyAsset,
            allowedAssets: Object.freeze([...this.#allowedAssets]),
            allowedNetworks: new Set(this.#allowedNetworks),
            allowedOrigins: this.#allowedOrigins ? new Set(this.#allowedOrigins) : undefined,
            maxAmountPerPayment: this.#maxAmountPerPayment,
            originOverrides: new Map(this.#originOverrides),
        });
    }
}

function assertNetwork(network: SolanaNetwork): SolanaNetwork {
    if (!NETWORKS.has(network)) throw new PermissionConfigurationError(`Invalid Solana network: ${network}`);
    return network;
}

function normalizeOrigin(value: string): string {
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new PermissionConfigurationError(`Invalid HTTP(S) origin: ${value}`);
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
        throw new PermissionConfigurationError(`Invalid HTTP(S) origin: ${value}`);
    }
    return url.origin;
}

function normalizeMint(network: SolanaNetwork, asset: string): string {
    const mint = resolveStablecoinMint(asset, network) ?? asset;
    try {
        return address(mint).toString();
    } catch {
        throw new PermissionConfigurationError(`Invalid Solana asset: ${asset}`);
    }
}

function matchesAsset(permission: AssetPermission, network: SolanaNetwork, mint: string): boolean {
    return permission.network === network && permission.mint === mint;
}

function denial(code: PermissionDeniedCode, message: string): PermissionDeniedError {
    return new PermissionDeniedError([{ code, message }]);
}
