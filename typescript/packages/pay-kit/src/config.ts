import { DEFAULT_RPC_URLS } from '@solana/mpp';
import type { Store } from 'mppx';

import { ConfigurationError, DemoSignerOnMainnetError, ProtocolNotSupportedError } from './errors.js';
import { type Stablecoin, STABLECOINS } from './price.js';
import { type Network, type NetworkSlug, type Protocol, toNetwork, toSolanaNetwork } from './protocol.js';
import { type KeychainSigner, type PayKitSigner, Signer } from './signer.js';

/** MPP protocol options. */
export type MppOptions = {
    /**
     * HMAC secret binding challenges to their contents. Resolved from
     * `PAY_KIT_MPP_SECRET` or `MPP_SECRET_KEY` when omitted; auto-generated
     * (with a warning) on localnet only.
     */
    readonly challengeBindingSecret?: string;
    /** Challenge TTL in seconds. `0` means never expires (dev only). */
    readonly expiresIn?: number;
    /**
     * Serve the interactive HTML payment page (the "Continue with Solana"
     * pay.sh experience) on `402`s for browser requests (`Accept: text/html`),
     * plus its service worker. API clients (JSON) still get the JSON `402`.
     * Default `false`.
     */
    readonly html?: boolean;
    readonly realm?: string;
};

/** x402 protocol options. Reserved for future scheme-specific settings. */
export type X402Options = Record<string, never>;

/** Merchant identity: where money lands and which key signs. */
export type OperatorParams = {
    /** Whether the operator signer sponsors transaction fees. */
    readonly feePayer?: boolean;
    /** Settlement address. Defaults to the signer's public key. */
    readonly recipient?: string;
    /**
     * Defaults to the demo signer (refused on mainnet). Raw kit / Keychain
     * signers are accepted and wrapped via {@link Signer.from}.
     */
    readonly signer?: KeychainSigner | PayKitSigner;
};

/** Resolved operator identity. */
export type Operator = {
    readonly feePayer: boolean;
    readonly recipient: string;
    readonly signer: PayKitSigner;
};

/** Parameters for {@link configure}. */
export type ConfigureParams = {
    /** Ordered protocol preference. */
    readonly accept?: readonly Protocol[];
    readonly mpp?: MppOptions;
    /** Canonical name (`solana_localnet`) or Solana slug (`localnet`). */
    readonly network?: Network | NetworkSlug;
    readonly operator?: OperatorParams;
    /** Run boot-time safety checks. */
    readonly preflight?: boolean;
    /** Replay-protection store. Use a persistent backend in production. */
    readonly replayStore?: Store.Store;
    /** Defaults to the public RPC endpoint for the network. */
    readonly rpcUrl?: string;
    /** Ordered settlement preference. */
    readonly stablecoins?: readonly Stablecoin[];
    readonly x402?: X402Options;
};

/** Resolved, immutable boot configuration. */
export type PayKitConfig = {
    readonly accept: readonly Protocol[];
    readonly mpp: {
        readonly challengeBindingSecret: string;
        readonly expiresIn: number;
        readonly html: boolean;
        readonly realm: string;
    };
    readonly network: Network;
    readonly operator: Operator;
    readonly preflight: boolean;
    readonly replayStore: Store.Store | undefined;
    readonly rpcUrl: string;
    readonly stablecoins: readonly Stablecoin[];
    readonly x402: Record<string, never>;
};

const DEFAULT_EXPIRES_IN_SECONDS = 120;

function resolveChallengeBindingSecret(network: Network, provided: string | undefined): string {
    const secret = provided ?? process.env.PAY_KIT_MPP_SECRET ?? process.env.MPP_SECRET_KEY;
    if (secret) return secret;
    if (network !== 'solana_localnet') {
        throw new ConfigurationError(
            'mpp.challengeBindingSecret is required outside localnet. Provide it in configure() ' +
                'or set PAY_KIT_MPP_SECRET.',
        );
    }
    console.warn(
        '[pay-kit] Generated an ephemeral MPP challenge secret (localnet). Challenges will not survive restarts.',
    );
    return crypto.randomUUID();
}

/**
 * Builds and validates the boot configuration. Everything downstream
 * (pricing, adapters, the dispatcher) derives its defaults from this object.
 *
 * @throws {DemoSignerOnMainnetError} when the demo signer is configured on mainnet.
 * @throws {ProtocolNotSupportedError} when `accept` requests a protocol this SDK does not ship.
 * @throws {ConfigurationError} on any other invalid combination.
 *
 * @example
 * ```ts
 * const config = await configure({
 *   network: 'solana_mainnet',
 *   operator: { signer: await Signer.env('OPERATOR_KEY') },
 *   rpcUrl: 'https://mainnet.helius-rpc.com/?api-key=...',
 * });
 * ```
 */
export async function configure(params: ConfigureParams = {}): Promise<PayKitConfig> {
    const network = toNetwork(params.network ?? 'solana_localnet');

    const accept = params.accept ?? ['mpp'];
    if (accept.length === 0) throw new ConfigurationError('accept must list at least one protocol.');
    for (const protocol of accept) {
        if (protocol !== 'mpp' && protocol !== 'x402') {
            throw new ProtocolNotSupportedError(
                `Protocol "${String(protocol)}" is not available in the TypeScript SDK yet (MPP and x402 only).`,
            );
        }
    }

    const stablecoins = params.stablecoins ?? ['USDC'];
    if (stablecoins.length === 0) throw new ConfigurationError('stablecoins must list at least one coin.');
    for (const coin of stablecoins) {
        if (!STABLECOINS.includes(coin)) {
            throw new ConfigurationError(`Unknown stablecoin "${coin}". Supported: ${STABLECOINS.join(', ')}.`);
        }
    }

    const provided = params.operator?.signer;
    const signer =
        provided === undefined
            ? await Signer.demo()
            : 'pubkey' in provided
              ? provided
              : Signer.from(provided, { feePayer: params.operator?.feePayer });
    if (signer.isDemo && network === 'solana_mainnet') {
        throw new DemoSignerOnMainnetError(
            'The demo signer is public and must not be used on mainnet. Provide operator.signer.',
        );
    }
    const operator: Operator = {
        feePayer: params.operator?.feePayer ?? true,
        recipient: params.operator?.recipient ?? signer.pubkey,
        signer,
    };

    const expiresIn = params.mpp?.expiresIn ?? DEFAULT_EXPIRES_IN_SECONDS;
    if (expiresIn < 0 || !Number.isInteger(expiresIn)) {
        throw new ConfigurationError('mpp.expiresIn must be a non-negative integer number of seconds.');
    }

    // The MPP challenge-binding secret is only meaningful when MPP is accepted;
    // an x402-only server must not be forced to provide one.
    const challengeBindingSecret = accept.includes('mpp')
        ? resolveChallengeBindingSecret(network, params.mpp?.challengeBindingSecret)
        : (params.mpp?.challengeBindingSecret ?? '');

    return Object.freeze({
        accept: Object.freeze([...accept]),
        mpp: Object.freeze({
            challengeBindingSecret,
            expiresIn,
            html: params.mpp?.html ?? false,
            realm: params.mpp?.realm ?? 'App',
        }),
        network,
        operator: Object.freeze(operator),
        preflight: params.preflight ?? true,
        replayStore: params.replayStore,
        rpcUrl: params.rpcUrl ?? DEFAULT_RPC_URLS[toSolanaNetwork(network)] ?? DEFAULT_RPC_URLS.mainnet,
        stablecoins: Object.freeze([...stablecoins]),
        x402: Object.freeze({}),
    });
}

/**
 * Builds the boot configuration from `PAY_KIT_`-prefixed environment
 * variables: `NETWORK`, `RPC_URL`, `ACCEPT` and `STABLECOINS`
 * (comma-separated), `OPERATOR_KEY` (any encoding {@link Signer.env}
 * accepts), `RECIPIENT`, `FEE_PAYER`, `MPP_REALM`, `MPP_SECRET`,
 * `MPP_EXPIRES_IN`, and `PREFLIGHT`.
 */
export async function configureFromEnv(prefix = 'PAY_KIT_'): Promise<PayKitConfig> {
    const env = (name: string) => process.env[`${prefix}${name}`]?.trim() || undefined;
    const list = (value: string | undefined) => value?.split(',').map(entry => entry.trim()) ?? undefined;

    const expiresIn = env('MPP_EXPIRES_IN');
    return await configure({
        accept: list(env('ACCEPT')) as readonly Protocol[] | undefined,
        mpp: {
            challengeBindingSecret: env('MPP_SECRET'),
            expiresIn: expiresIn === undefined ? undefined : Number(expiresIn),
            realm: env('MPP_REALM'),
        },
        network: env('NETWORK') as Network | undefined,
        operator: {
            feePayer: env('FEE_PAYER') === undefined ? undefined : env('FEE_PAYER') !== 'false',
            recipient: env('RECIPIENT'),
            signer: await Signer.env(`${prefix}OPERATOR_KEY`),
        },
        preflight: env('PREFLIGHT') === undefined ? undefined : env('PREFLIGHT') !== 'false',
        rpcUrl: env('RPC_URL'),
    });
}
