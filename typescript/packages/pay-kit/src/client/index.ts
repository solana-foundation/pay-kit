/**
 * `@solana/pay-kit/client` — the client counterpart to {@link import('../paykit.js').createPayKit}.
 *
 * A single config-object factory returns a payment-aware `fetch`: it issues the
 * request, and on a `402` it reads the challenge, pays with the right protocol,
 * and retries — dispatching by the challenge header (x402's `payment-required`
 * vs MPP's `www-authenticate`). The shape mirrors the Rust client's
 * parse-challenge → build-header → retry flow, packaged as one instance like
 * the server's `createPayKit`.
 *
 * Protocols stay invisible to callers: `accept` is the only knob, and one
 * `signer` drives both rails (an `@solana/kit` `KeyPairSigner` satisfies the
 * x402 `ClientSvmSigner` and the MPP client methods).
 */
import type { KeyPairSigner } from '@solana/kit';
import {
    Challenge,
    resolveStablecoinMint,
    selectSolanaChargeChallengeFromResponse,
    serializeSubscriptionAccessCredential,
    solana,
} from '@solana/mpp/client';
import { x402Client, x402HTTPClient } from '@x402/core/client';
import type { Network, PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { ExactSvmScheme } from '@x402/svm/exact/client';
import { UptoSvmScheme } from '@x402/svm/upto/client';

import { ConfigurationError } from '../errors.js';
import type { Protocol } from '../protocol.js';
import {
    ClientPermissions,
    PermissionDeniedError,
    type PermissionRejection,
    type SolanaNetwork,
} from './permissions.js';

export * from './permissions.js';

/** Capture the caller's fetch implementation once for challenge probes and retries. */
const nativeFetch: typeof fetch = globalThis.fetch.bind(globalThis);

/** Options for {@link createPayKitClient}. */
export type PayKitClientOptions = {
    /** Protocols the client will pay with. Defaults to `['x402', 'mpp']`. */
    readonly accept?: readonly Protocol[];
    /** Solana cluster used to pin default permissions. Defaults to `mainnet`. */
    readonly network?: SolanaNetwork;
    /** Progress callback, forwarded to the MPP charge/subscription methods. */
    readonly onProgress?: (event: unknown) => void;
    /** Payment permissions. Pass `false` to allow every supported payment. */
    readonly permissions?: ClientPermissions | false;
    /** RPC endpoint used to build payments (sign transfers, open channels). */
    readonly rpcUrl: string;
    /** The payer signer — drives both x402 and MPP. */
    readonly signer: KeyPairSigner;
};

/** The PayKit client instance: a payment-aware `fetch`. */
export type PayKitClient = {
    /**
     * Like `fetch`, but transparently settles a `402`: reads the challenge,
     * pays with the matching protocol, and retries. Non-402 responses pass
     * through untouched. When the server offers more than one protocol, pass
     * `protocol` to force one (e.g. `'x402'`); otherwise MPP is preferred.
     */
    readonly fetch: (input: RequestInfo | URL, init?: RequestInit, protocol?: Protocol) => Promise<Response>;
};

/** Fluent builder for {@link PayKitClient}. */
export class PayKitClientBuilder {
    #accept: readonly Protocol[] | undefined;
    #network: SolanaNetwork = 'mainnet';
    #onProgress: ((event: unknown) => void) | undefined;
    #permissions: ClientPermissions | false | undefined;
    #rpcUrl: string | undefined;
    #signer: KeyPairSigner | undefined;

    /** Set the payer signer. */
    signer(signer: KeyPairSigner): this {
        this.#signer = signer;
        return this;
    }

    /** Set the Solana RPC URL. */
    rpcUrl(rpcUrl: string): this {
        this.#rpcUrl = rpcUrl;
        return this;
    }

    /** Set the Solana cluster. Defaults to `mainnet`. */
    network(network: SolanaNetwork): this {
        this.#network = network;
        return this;
    }

    /** Restrict the protocols this client may answer. */
    accept(protocols: readonly Protocol[]): this {
        this.#accept = protocols;
        return this;
    }

    /** Replace the default permission policy. */
    permissions(permissions: ClientPermissions | false): this {
        this.#permissions = permissions;
        return this;
    }

    /** Set a payment progress callback. */
    onProgress(callback: (event: unknown) => void): this {
        this.#onProgress = callback;
        return this;
    }

    /** Validate the configuration and build the payment client. */
    build(): Promise<PayKitClient> {
        if (!this.#signer) throw new ConfigurationError('PayKitClient requires a signer');
        if (!this.#rpcUrl) throw new ConfigurationError('PayKitClient requires an RPC URL');
        return createPayKitClient({
            accept: this.#accept,
            network: this.#network,
            onProgress: this.#onProgress,
            permissions: this.#permissions,
            rpcUrl: this.#rpcUrl,
            signer: this.#signer,
        });
    }
}

/** Builder entry point matching the Rust `PayKitClient::builder()` API. */
export const PayKitClient = Object.freeze({
    builder: (): PayKitClientBuilder => new PayKitClientBuilder(),
});

/** Parse the `intent` from an MPP `www-authenticate` challenge value. */
function mppIntent(header: string | null): string | undefined {
    return header?.match(/intent="([^"]+)"/)?.[1];
}

function withHeader(request: Request, name: string, value: string): Request {
    const headers = new Headers(request.headers);
    headers.set(name, value);
    return new Request(request.clone(), { headers });
}

/**
 * Creates a PayKit client: a `fetch` that pays `402`s over x402 or MPP,
 * dispatched by the server's challenge. The client counterpart to
 * {@link import('../paykit.js').createPayKit}.
 *
 * @example
 * ```ts
 * const client = await createPayKitClient({ signer, rpcUrl, accept: ['x402', 'mpp'] });
 * const res = await client.fetch('/x402/joke');
 * ```
 *
 * @param options - Signer, RPC, accepted protocols, optional progress callback
 * @returns The client instance
 */
export function createPayKitClient(options: PayKitClientOptions): Promise<PayKitClient> {
    const accept = options.accept ?? ['x402', 'mpp'];
    if (accept.length === 0) throw new ConfigurationError('PayKitClient must accept at least one protocol');
    const acceptsX402 = accept.includes('x402');
    const acceptsMpp = accept.includes('mpp');
    const onProgress = options.onProgress;
    const network = options.network ?? 'mainnet';
    const permissions =
        options.permissions === false
            ? ClientPermissions.unrestricted()
            : (options.permissions ?? ClientPermissions.builder().onlyNetwork(network).build());

    // x402: one client with the SVM `exact` + `upto` schemes; the HTTP helper
    // turns a parsed 402 into the payment header(s) to retry with. The schemes
    // are pinned to `rpcUrl` — otherwise they derive their RPC from the
    // challenge's network (which for localnet is tagged as devnet's CAIP-2),
    // building a transfer with a blockhash the settlement RPC would reject.
    let http: x402HTTPClient | undefined;
    if (acceptsX402) {
        const svm = { rpcUrl: options.rpcUrl };
        const client = new x402Client();
        // PayKit's protocol-neutral permissions are the source of truth. Avoid
        // applying @x402/core's separate defaults after they have authorized a
        // challenge (including when callers explicitly choose unrestricted).
        client.setSpendControls(false);
        client.register('solana:*' as Network, new ExactSvmScheme(options.signer, svm));
        client.register('solana:*' as Network, new UptoSvmScheme(options.signer, svm));
        http = new x402HTTPClient(client);
    }

    // MPP charge + subscription credentials are built from the challenge we
    // already authorized, then the original request is retried directly.
    const subscriptionCredentials = new Map<string, string>();
    const forward = onProgress ? (event: unknown) => onProgress(event) : undefined;

    async function payFetch(input: RequestInfo | URL, init?: RequestInit, protocol?: Protocol): Promise<Response> {
        // Keep one pristine request and send clones so a POST body can be
        // replayed exactly once after the 402 challenge.
        const request = new Request(input, init);
        const resource = request.url;
        const subscriptionCredential = subscriptionCredentials.get(resource);
        const probe = subscriptionCredential
            ? await nativeFetch(withHeader(request, 'Authorization', subscriptionCredential))
            : await nativeFetch(request.clone());
        if (probe.status !== 402) return probe;
        if (probe.redirected) {
            throw new PermissionDeniedError([
                {
                    code: 'invalid_challenge_terms',
                    message: 'Refusing to pay a 402 reached through an HTTP redirect',
                },
            ]);
        }

        // `protocol` (optional) forces a rail when the server offers both;
        // otherwise MPP is preferred (richer progress, canonical for
        // charge/subscription), with x402 used when it's the only offer.
        const useMpp = acceptsMpp && protocol !== 'x402';
        const useX402 = acceptsX402 && protocol !== 'mpp';
        const origin = new URL(probe.url || resource).origin;
        const rejections: PermissionRejection[] = [];

        if (useMpp && probe.headers.get('www-authenticate')) {
            const intent = mppIntent(probe.headers.get('www-authenticate'));
            if (intent === 'session') {
                throw new ConfigurationError(
                    'Session payments are streaming; use the dedicated session client (createSessionFetch), not client.fetch.',
                );
            }
            const challenge = selectSolanaChargeChallengeFromResponse(probe);
            if (challenge) {
                const challengeNetwork = normalizeNetwork(
                    challenge.request.methodDetails.network ?? 'mainnet',
                    network,
                );
                const mint = resolveStablecoinMint(challenge.request.currency, challengeNetwork);
                if (mint) {
                    try {
                        const authorization = permissions.authorize({
                            amount: challengeAmount(challenge.request.amount),
                            mint,
                            network: challengeNetwork,
                            origin,
                        });
                        const method = solana.charge({
                            expectedNetwork: challengeNetwork,
                            maxAmount: authorization.maxAmountAtomic,
                            onProgress: forward,
                            rpcUrl: options.rpcUrl,
                            signer: options.signer,
                        });
                        const authorizationHeader = await method.createCredential({ challenge });
                        return await nativeFetch(withHeader(request, 'Authorization', authorizationHeader));
                    } catch (error) {
                        if (!(error instanceof PermissionDeniedError)) throw error;
                        rejections.push(...error.rejections);
                    }
                }
            } else if (intent === 'subscription') {
                const subscriptionChallenge = Challenge.fromResponseList(probe).find(
                    candidate => candidate.method === 'solana' && candidate.intent === 'subscription',
                );
                const subscriptionTerms = subscriptionRequest(subscriptionChallenge?.request);
                if (subscriptionChallenge && subscriptionTerms) {
                    try {
                        const challengeNetwork = normalizeNetwork(
                            subscriptionTerms.methodDetails.network ?? 'mainnet',
                            network,
                        );
                        permissions.authorize({
                            amount: challengeAmount(subscriptionTerms.amount),
                            mint: subscriptionTerms.currency,
                            network: challengeNetwork,
                            origin,
                        });
                        const method = solana.subscription({
                            onAuthentication: access => {
                                subscriptionCredentials.set(resource, serializeSubscriptionAccessCredential(access));
                            },
                            onProgress: forward,
                            rpcUrl: options.rpcUrl,
                            signer: options.signer,
                        });
                        const authorizationHeader = await method.createCredential({
                            challenge: subscriptionChallenge as never,
                        });
                        return await nativeFetch(withHeader(request, 'Authorization', authorizationHeader));
                    } catch (error) {
                        if (!(error instanceof PermissionDeniedError)) throw error;
                        rejections.push(...error.rejections);
                    }
                }
            }
        }

        if (useX402 && http && probe.headers.get('payment-required')) {
            // Parse the challenge → build + sign the payment → encode the
            // `X-PAYMENT` header → retry. (`handlePaymentRequired` is only a
            // pre-payment hook dispatcher; the payload is built explicitly.)
            // Emit the same progress vocabulary as the MPP path so callers get a
            // uniform flow (challenge → signing → paying → paid) on both rails.
            const required = http.getPaymentRequiredResponse(name => probe.headers.get(name));
            const permitted: PaymentRequirements[] = [];
            for (const requirement of required.accepts ?? []) {
                try {
                    permissions.authorize({
                        amount: challengeAmount(requirement.amount),
                        mint: requirement.asset,
                        network: normalizeNetwork(requirement.network, network),
                        origin,
                    });
                    permitted.push(requirement);
                } catch (error) {
                    if (!(error instanceof PermissionDeniedError)) throw error;
                    rejections.push(...error.rejections);
                }
            }
            if (permitted.length === 0) {
                if (rejections.length > 0) throw new PermissionDeniedError(rejections);
                return probe;
            }
            const permittedRequired: PaymentRequired = { ...required, accepts: permitted };
            const requirement = permitted[0];
            // Decimals are intentionally omitted: the x402 requirement carries
            // only the asset address, not its precision. Hardcoding 6 would
            // misreport non-6-decimal assets, so leave it to the consumer to
            // resolve from asset metadata.
            onProgress?.({
                amount: requirement?.amount,
                currency: requirement?.asset,
                recipient: requirement?.payTo,
                type: 'challenge',
            });
            onProgress?.({ type: 'signing' });
            const payload = await http.createPaymentPayload(permittedRequired);
            const payHeaders = http.encodePaymentSignatureHeader(payload);
            const headers = new Headers(request.headers);
            for (const [name, value] of Object.entries(payHeaders)) headers.set(name, value);
            onProgress?.({ type: 'paying' });
            const response = await nativeFetch(new Request(request.clone(), { headers }));
            if (response.ok) {
                try {
                    const settle = http.getPaymentSettleResponse(name => response.headers.get(name));
                    onProgress?.({ signature: settle.transaction ?? '', type: 'paid' });
                } catch {
                    // No settle response to surface; the flow rests at "broadcast".
                }
            }
            return response;
        }

        if (rejections.length > 0) throw new PermissionDeniedError(rejections);

        return probe;
    }

    return Promise.resolve({ fetch: payFetch });
}

function normalizeNetwork(value: string, configured: SolanaNetwork): SolanaNetwork {
    if (value === 'mainnet' || value === 'mainnet-beta' || value === 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp') {
        return 'mainnet';
    }
    if (value === 'localnet') return 'localnet';
    if (value === 'devnet' || value === 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1') {
        return configured === 'localnet' ? 'localnet' : 'devnet';
    }
    throw new PermissionDeniedError([
        { code: 'invalid_challenge_terms', message: `Unsupported Solana network: ${value}` },
    ]);
}

function challengeAmount(value: string): bigint {
    if (!/^\d+$/.test(value)) {
        throw new PermissionDeniedError([
            { code: 'invalid_challenge_terms', message: `Invalid payment amount: ${JSON.stringify(value)}` },
        ]);
    }
    return BigInt(value);
}

function subscriptionRequest(
    value: unknown,
): { amount: string; currency: string; methodDetails: { network?: string } } | undefined {
    if (!value || typeof value !== 'object') return undefined;
    const request = value as Record<string, unknown>;
    if (typeof request.amount !== 'string' || typeof request.currency !== 'string') return undefined;
    if (!request.methodDetails || typeof request.methodDetails !== 'object') return undefined;
    const methodDetails = request.methodDetails as Record<string, unknown>;
    if (methodDetails.network !== undefined && typeof methodDetails.network !== 'string') return undefined;
    return {
        amount: request.amount,
        currency: request.currency,
        methodDetails: { network: methodDetails.network },
    };
}
