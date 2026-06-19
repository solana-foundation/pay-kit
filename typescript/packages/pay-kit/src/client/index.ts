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
import { Mppx, solana } from '@solana/mpp/client';
import { x402Client, x402HTTPClient } from '@x402/core/client';
import type { Network } from '@x402/core/types';
import { ExactSvmScheme } from '@x402/svm/exact/client';
import { UptoSvmScheme } from '@x402/svm/upto/client';

import { ConfigurationError } from '../errors.js';
import type { Protocol } from '../protocol.js';

/** Capture native fetch before `Mppx.create()` polyfills `globalThis.fetch`. */
const nativeFetch: typeof fetch = globalThis.fetch.bind(globalThis);

/** Options for {@link createPayKitClient}. */
export type PayKitClientOptions = {
    /** Protocols the client will pay with. Defaults to `['x402', 'mpp']`. */
    readonly accept?: readonly Protocol[];
    /** Progress callback, forwarded to the MPP charge/subscription methods. */
    readonly onProgress?: (event: unknown) => void;
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

/** Parse the `intent` from an MPP `www-authenticate` challenge value. */
function mppIntent(header: string | null): string | undefined {
    return header?.match(/intent="([^"]+)"/)?.[1];
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
    const acceptsX402 = accept.includes('x402');
    const acceptsMpp = accept.includes('mpp');
    const onProgress = options.onProgress;

    // x402: one client with the SVM `exact` + `upto` schemes; the HTTP helper
    // turns a parsed 402 into the payment header(s) to retry with. The schemes
    // are pinned to `rpcUrl` — otherwise they derive their RPC from the
    // challenge's network (which for localnet is tagged as devnet's CAIP-2),
    // building a transfer with a blockhash the settlement RPC would reject.
    let http: x402HTTPClient | undefined;
    if (acceptsX402) {
        const svm = { rpcUrl: options.rpcUrl };
        const client = new x402Client();
        client.register('solana:*' as Network, new ExactSvmScheme(options.signer, svm));
        client.register('solana:*' as Network, new UptoSvmScheme(options.signer, svm));
        http = new x402HTTPClient(client);
    }

    // MPP: lazily-built `Mppx` instances (creating one polyfills global fetch,
    // hence the captured `nativeFetch` above). Charge + subscription are
    // 402→pay→retry; the instance's own `fetch` handles that loop.
    let chargeMppx: ReturnType<typeof Mppx.create> | undefined;
    let subscriptionMppx: ReturnType<typeof Mppx.create> | undefined;
    const forward = onProgress ? (event: unknown) => onProgress(event) : undefined;
    const chargeClient = (): ReturnType<typeof Mppx.create> =>
        (chargeMppx ??= Mppx.create({
            methods: [solana.charge({ onProgress: forward, rpcUrl: options.rpcUrl, signer: options.signer })],
        }));
    const subscriptionClient = (): ReturnType<typeof Mppx.create> =>
        (subscriptionMppx ??= Mppx.create({
            methods: [solana.subscription({ onProgress: forward, rpcUrl: options.rpcUrl, signer: options.signer })],
        }));

    async function payFetch(input: RequestInfo | URL, init?: RequestInit, protocol?: Protocol): Promise<Response> {
        const probe = await nativeFetch(input, init);
        if (probe.status !== 402) return probe;

        // `protocol` (optional) forces a rail when the server offers both;
        // otherwise MPP is preferred (richer progress, canonical for
        // charge/subscription), with x402 used when it's the only offer.
        const useMpp = acceptsMpp && protocol !== 'x402';
        const useX402 = acceptsX402 && protocol !== 'mpp';

        if (useMpp && probe.headers.get('www-authenticate')) {
            const intent = mppIntent(probe.headers.get('www-authenticate'));
            if (intent === 'session') {
                throw new ConfigurationError(
                    'Session payments are streaming; use the dedicated session client (createSessionFetch), not client.fetch.',
                );
            }
            const mppx = intent === 'subscription' ? subscriptionClient() : chargeClient();
            return await mppx.fetch(input as string, init);
        }

        if (useX402 && http && probe.headers.get('payment-required')) {
            // Parse the challenge → build + sign the payment → encode the
            // `X-PAYMENT` header → retry. (`handlePaymentRequired` is only a
            // pre-payment hook dispatcher; the payload is built explicitly.)
            // Emit the same progress vocabulary as the MPP path so callers get a
            // uniform flow (challenge → signing → paying → paid) on both rails.
            const required = http.getPaymentRequiredResponse(name => probe.headers.get(name));
            const requirement = required.accepts?.[0];
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
            const payload = await http.createPaymentPayload(required);
            const payHeaders = http.encodePaymentSignatureHeader(payload);
            const headers = new Headers(init?.headers);
            for (const [name, value] of Object.entries(payHeaders)) headers.set(name, value);
            onProgress?.({ type: 'paying' });
            const response = await nativeFetch(input, { ...init, headers });
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

        return probe;
    }

    return Promise.resolve({ fetch: payFetch });
}
