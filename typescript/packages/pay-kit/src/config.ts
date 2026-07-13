import { DEFAULT_RPC_URLS } from '@solana/mpp';
import type { SessionStore } from '@solana/mpp/server';
import type { Store } from 'mppx';

import { ConfigurationError, DemoSignerOnMainnetError, ProtocolNotSupportedError } from './errors.js';
import { type Stablecoin, STABLECOINS } from './price.js';
import { type Network, type NetworkSlug, type Protocol, toNetwork, toSolanaNetwork } from './protocol.js';
import { DEMO_SIGNER_PUBLIC_KEY, type KeychainSigner, type PayKitSigner, Signer } from './signer.js';
import {
    type AtomicSubscriptionReplayStore,
    createUnsafeMemorySubscriptionReplayStore,
} from './subscription-replay-store.js';

/** MPP protocol options. */
export type MppOptions = {
    /**
     * HMAC secret binding challenges to their contents. Resolved from
     * `PAY_KIT_MPP_SECRET` or `MPP_SECRET_KEY` when omitted; auto-generated
     * (with a warning) on localnet only.
     */
    readonly challengeBindingSecret?: string;
    /** Challenge TTL in seconds. `0` uses Mppx's fail-closed default TTL. */
    readonly expiresIn?: number;
    /**
     * Serve the interactive HTML payment page (the "Continue with Solana"
     * pay.sh experience) on `402`s for browser requests (`Accept: text/html`),
     * plus its service worker. API clients (JSON) still get the JSON `402`.
     * Default `false`.
     */
    readonly html?: boolean;
    readonly realm?: string;
    /**
     * Storage for MPP session channels. Provide a durable, shared store in
     * production because it records voucher and delivery state.
     */
    readonly sessionStore?: SessionStore;
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
    /**
     * Replay-protection store. Subscription gates require the atomic
     * {@link AtomicSubscriptionReplayStore} contract; use a shared, durable
     * implementation in production.
     */
    readonly replayStore?: AtomicSubscriptionReplayStore | Store.Store;
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
        readonly sessionStore: SessionStore | undefined;
    };
    readonly network: Network;
    readonly operator: Operator;
    readonly preflight: boolean;
    readonly replayStore: AtomicSubscriptionReplayStore | Store.Store | undefined;
    readonly rpcUrl: string;
    readonly stablecoins: readonly Stablecoin[];
    readonly x402: Record<string, never>;
};

const DEFAULT_EXPIRES_IN_SECONDS = 120;
const MIN_CHALLENGE_BINDING_SECRET_BYTES = 32;
const ALLOW_INMEMORY_REPLAY_STORE_ENV = 'PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE';
const SUPPORTED_NETWORKS: ReadonlySet<Network> = new Set(['solana_devnet', 'solana_localnet', 'solana_mainnet']);

function validateNetwork(network: Network): void {
    if (!SUPPORTED_NETWORKS.has(network)) {
        throw new ConfigurationError(`Unknown network "${String(network)}".`);
    }
}

function validateAccept(accept: readonly Protocol[]): void {
    if (accept.length === 0) throw new ConfigurationError('accept must list at least one protocol.');
    for (const protocol of accept) {
        if (protocol !== 'mpp' && protocol !== 'x402') {
            throw new ProtocolNotSupportedError(
                `Protocol "${String(protocol)}" is not available in the TypeScript SDK yet (MPP and x402 only).`,
            );
        }
    }
}

function validateStablecoins(stablecoins: readonly Stablecoin[]): void {
    if (stablecoins.length === 0) throw new ConfigurationError('stablecoins must list at least one coin.');
    for (const coin of stablecoins) {
        if (!STABLECOINS.includes(coin)) {
            throw new ConfigurationError(`Unknown stablecoin "${coin}". Supported: ${STABLECOINS.join(', ')}.`);
        }
    }
}

function validateOperator(network: Network, operator: Operator): void {
    if (network === 'solana_mainnet' && operator.signer.signer.address === DEMO_SIGNER_PUBLIC_KEY) {
        throw new DemoSignerOnMainnetError(
            'The demo signer is public and must not be used on mainnet. Provide operator.signer.',
        );
    }
}

function validateChallengeBindingSecret(secret: unknown): asserts secret is string {
    if (typeof secret !== 'string' || secret.length === 0) {
        throw new ConfigurationError('mpp.challengeBindingSecret must be a non-empty string.');
    }
}

/**
 * Whether a process-local, in-memory store is permitted on this cluster:
 * always on localnet, and on devnet only under the explicit
 * `PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1` development opt-in. Mainnet never
 * qualifies. The single gate every in-memory fallback (charge replay store and
 * session store) consults so the policy cannot drift between them.
 */
export function inMemoryStoresAllowed(network: Network): boolean {
    return (
        network === 'solana_localnet' ||
        (network === 'solana_devnet' && process.env[ALLOW_INMEMORY_REPLAY_STORE_ENV] === '1')
    );
}

/**
 * Every accepted protocol that settles an on-chain transaction needs a shared,
 * durable replay store: both MPP charge/subscription and x402 exact/upto fence
 * a broadcast signature against replay. An x402-only server is as exposed to a
 * double-settlement as an MPP one, so the config-layer requirement covers both.
 */
function requiresSettlementReplayStore(accept: readonly Protocol[]): boolean {
    return accept.includes('mpp') || accept.includes('x402');
}

function validateReplayStore(config: Pick<PayKitConfig, 'accept' | 'network' | 'replayStore'>): void {
    if (!requiresSettlementReplayStore(config.accept) || config.network === 'solana_localnet') return;

    const store = config.replayStore;
    if (store === undefined) {
        if (inMemoryStoresAllowed(config.network)) return;
        throw new ConfigurationError(
            `no shared replay store configured outside localnet; provide replayStore` +
                ` or, on devnet only, set ${ALLOW_INMEMORY_REPLAY_STORE_ENV}=1`,
        );
    }
    if (store === null || typeof store !== 'object' || typeof (store as { reserve?: unknown }).reserve !== 'function') {
        throw new ConfigurationError('replayStore outside localnet must provide an atomic reserve() operation.');
    }
    const replayStore = store as AtomicSubscriptionReplayStore;
    if (replayStore.isShared !== true || replayStore.isDurable !== true) {
        // A process-local in-memory replay store keeps charge/x402 replay
        // protection within a single process; permit it only under the dev
        // opt-in. Subscription gates still require durable+shared (enforced in
        // the MPP adapter), so this opt-in never weakens subscription
        // activation replay.
        if (inMemoryStoresAllowed(config.network)) return;
        throw new ConfigurationError('replayStore outside localnet must set isShared=true and isDurable=true.');
    }
}

export function validateMppConfig(
    config: Pick<PayKitConfig, 'accept' | 'network'> & {
        readonly mpp: Pick<PayKitConfig['mpp'], 'challengeBindingSecret' | 'expiresIn'>;
    },
): void {
    const { challengeBindingSecret, expiresIn } = config.mpp;
    if (config.accept.includes('mpp')) validateChallengeBindingSecret(challengeBindingSecret);
    if (expiresIn < 0 || !Number.isInteger(expiresIn)) {
        throw new ConfigurationError('mpp.expiresIn must be a non-negative integer number of seconds.');
    }
    if (expiresIn > 0 && !Number.isFinite(new Date(Date.now() + expiresIn * 1000).getTime())) {
        throw new ConfigurationError('mpp.expiresIn must produce a valid expiration date.');
    }
    if (
        config.accept.includes('mpp') &&
        config.network !== 'solana_localnet' &&
        new TextEncoder().encode(challengeBindingSecret).byteLength < MIN_CHALLENGE_BINDING_SECRET_BYTES
    ) {
        throw new ConfigurationError(
            `mpp.challengeBindingSecret must be at least ${MIN_CHALLENGE_BINDING_SECRET_BYTES} UTF-8 bytes outside localnet.`,
        );
    }
}

/** Revalidate every security-relevant invariant on a resolved config. */
export function validatePayKitConfig(config: PayKitConfig): void {
    validateNetwork(config.network);
    validateAccept(config.accept);
    validateStablecoins(config.stablecoins);
    validateOperator(config.network, config.operator);
    validateMppConfig(config);
    validateReplayStore(config);
}

function freezePayKitSigner(signer: PayKitSigner): PayKitSigner {
    return Object.freeze({
        isDemo: signer.isDemo,
        isFeePayer: signer.isFeePayer,
        pubkey: signer.pubkey,
        sign: signer.sign.bind(signer),
        signer: signer.signer,
    });
}

/** Take an immutable snapshot so caller mutation cannot drift adapter policy. */
export function freezePayKitConfig(config: PayKitConfig): PayKitConfig {
    return Object.freeze({
        ...config,
        accept: Object.freeze([...config.accept]),
        mpp: Object.freeze({ ...config.mpp }),
        operator: Object.freeze({
            ...config.operator,
            signer: freezePayKitSigner(config.operator.signer),
        }),
        stablecoins: Object.freeze([...config.stablecoins]),
        x402: Object.freeze({ ...config.x402 }),
    });
}

function resolveChallengeBindingSecret(network: Network, provided: unknown): string {
    if (provided !== undefined) {
        validateChallengeBindingSecret(provided);
        return provided;
    }
    const secret = process.env.PAY_KIT_MPP_SECRET ?? process.env.MPP_SECRET_KEY;
    if (secret !== undefined && secret.length > 0) return secret;
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
    validateNetwork(network);

    const accept = params.accept ?? ['mpp'];
    validateAccept(accept);

    const stablecoins = params.stablecoins ?? ['USDC'];
    validateStablecoins(stablecoins);

    const provided = params.operator?.signer;
    const signer =
        provided === undefined
            ? await Signer.demo()
            : 'pubkey' in provided
              ? provided
              : Signer.from(provided, { feePayer: params.operator?.feePayer });
    const operator: Operator = {
        feePayer: params.operator?.feePayer ?? true,
        recipient: params.operator?.recipient ?? signer.pubkey,
        signer,
    };
    validateOperator(network, operator);

    const expiresIn = params.mpp?.expiresIn ?? DEFAULT_EXPIRES_IN_SECONDS;
    // The MPP challenge-binding secret is only meaningful when MPP is accepted;
    // an x402-only server must not be forced to provide one.
    const challengeBindingSecret = accept.includes('mpp')
        ? resolveChallengeBindingSecret(network, params.mpp?.challengeBindingSecret)
        : (params.mpp?.challengeBindingSecret ?? '');

    // When the devnet in-memory opt-in is set and no replay store was supplied,
    // materialize ONE process-local store so the same instance reaches every
    // settlement adapter (charge, subscription, x402). Charge/x402 then run with
    // in-memory replay protection; the subscription adapter still rejects it
    // (non-durable) with a clear error, so this never silently boots a
    // subscription unprotected. Localnet is left untouched (adapters build
    // their own).
    const replayStore =
        params.replayStore === undefined &&
        requiresSettlementReplayStore(accept) &&
        network === 'solana_devnet' &&
        process.env[ALLOW_INMEMORY_REPLAY_STORE_ENV] === '1'
            ? createUnsafeMemorySubscriptionReplayStore()
            : params.replayStore;

    const resolved: PayKitConfig = {
        accept,
        mpp: {
            challengeBindingSecret,
            expiresIn,
            html: params.mpp?.html ?? false,
            realm: params.mpp?.realm ?? 'App',
            sessionStore: params.mpp?.sessionStore,
        },
        network,
        operator,
        preflight: params.preflight ?? true,
        replayStore,
        rpcUrl: params.rpcUrl ?? DEFAULT_RPC_URLS[toSolanaNetwork(network)] ?? DEFAULT_RPC_URLS.mainnet,
        stablecoins,
        x402: {},
    };
    validatePayKitConfig(resolved);
    return freezePayKitConfig(resolved);
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
