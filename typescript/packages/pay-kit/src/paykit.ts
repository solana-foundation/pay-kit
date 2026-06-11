import type { ProtocolAdapter } from './adapter.js';
import { createMppAdapter } from './adapters/mpp.js';
import type { Challenge } from './challenge.js';
import type { PayKitConfig } from './config.js';
import { ConfigurationError, InvalidProofError } from './errors.js';
import { Gate } from './gate.js';
import type { Payment } from './payment.js';
import { Price } from './price.js';
import {
    createPricing,
    DynamicGate,
    gateDefaults,
    type GateResolver,
    type InlineGateParams,
    Pricing,
} from './pricing.js';

/**
 * Anything that names a gate: a {@link Gate}, a catalogue name, a bare
 * {@link Price} (anonymous inline gate), or a per-request resolver.
 */
export type GateRef = DynamicGate | Gate | GateResolver | Price | string;

/** The request did not carry a valid payment; respond with `response`. */
export type PaymentDenied = {
    readonly challenge: Challenge;
    readonly response: Response;
    readonly status: 402;
};

/** The payment verified and settled; reply through `withSettlement`. */
export type PaymentGranted = {
    readonly payment: Payment;
    readonly status: 200;
    /** Returns `response` with the settlement headers merged in. */
    readonly withSettlement: (response: Response) => Response;
};

/** Result of {@link PayKit.requirePayment}. */
export type RequirePaymentResult = PaymentDenied | PaymentGranted;

/**
 * The PayKit server surface: the three request verbs shared across the SDK
 * family, over web-standard `Request`/`Response`.
 */
export type PayKit = {
    readonly config: PayKitConfig;
    /** Whether `request` already carries a verified payment (optionally for a specific gate). */
    readonly paid: (request: Request, gateName?: string) => boolean;
    /** The verified payment on `request`, if any. */
    readonly payment: (request: Request) => Payment | undefined;
    /** Verify-or-deny: settles a credential or produces the 402 challenge. */
    readonly requirePayment: (request: Request, gate: GateRef) => Promise<RequirePaymentResult>;
};

/**
 * Builds the PayKit dispatcher from a boot config: gate resolution, protocol
 * adapter selection, 402 rendering, settlement-header propagation.
 *
 * `pricing` accepts either a built {@link Pricing} or inline gate
 * definitions, which are validated immediately against the config defaults.
 *
 * @example
 * ```ts
 * const paykit = createPayKit(await configure(), {
 *   pricing: { report: { amount: usd('0.10') } },
 * });
 *
 * // In a fetch-style handler:
 * const result = await paykit.requirePayment(request, 'report');
 * if (result.status === 402) return result.response;
 * return result.withSettlement(Response.json({ ok: true, tx: result.payment.transaction }));
 * ```
 */
export function createPayKit(
    config: PayKitConfig,
    options: {
        adapters?: readonly ProtocolAdapter[];
        pricing?: Pricing | Readonly<Record<string, GateResolver | InlineGateParams>>;
    } = {},
): PayKit {
    const adapters =
        options.adapters ??
        config.accept.map(protocol => {
            // configure() already rejects protocols without a shipped adapter.
            if (protocol !== 'mpp') throw new ConfigurationError(`No adapter for protocol "${protocol}".`);
            return createMppAdapter(config);
        });
    const pricing =
        options.pricing === undefined || options.pricing instanceof Pricing
            ? options.pricing
            : createPricing(config, options.pricing);
    const payments = new WeakMap<Request, Payment>();
    const defaults = gateDefaults(config);

    async function resolveGate(ref: GateRef, request: Request): Promise<Gate> {
        if (ref instanceof Gate) return ref;
        if (ref instanceof DynamicGate) return await ref.resolve(request);
        if (ref instanceof Price) return Gate.create({ amount: ref, name: 'inline' }, defaults);
        if (typeof ref === 'string') {
            if (!pricing) {
                throw new ConfigurationError(
                    `Gate "${ref}" referenced by name but no Pricing catalogue was passed to createPayKit().`,
                );
            }
            const gate = pricing.gate(ref);
            return gate instanceof DynamicGate ? await gate.resolve(request) : gate;
        }
        const result = await ref(request);
        const params: InlineGateParams = result instanceof Price ? { amount: result } : result;
        return Gate.create({ ...params, name: 'inline' }, defaults);
    }

    async function buildChallenge(gate: Gate, request: Request, eligible: readonly ProtocolAdapter[]) {
        const headers: Record<string, string> = {};
        const accepts = [];
        for (const adapter of eligible) {
            accepts.push(await adapter.acceptsEntry(gate, request));
            Object.assign(headers, await adapter.challengeHeaders(gate, request));
        }
        const challenge: Challenge = { accepts, headers, resource: new URL(request.url).pathname };
        return challenge;
    }

    function render402(challenge: Challenge, body: Record<string, unknown>): Response {
        return new Response(JSON.stringify(body), {
            headers: { ...challenge.headers, 'content-type': 'application/json' },
            status: 402,
        });
    }

    return {
        config,

        paid(request: Request, gateName?: string): boolean {
            const payment = payments.get(request);
            return payment !== undefined && (gateName === undefined || payment.gateName === gateName);
        },

        payment(request: Request): Payment | undefined {
            return payments.get(request);
        },

        async requirePayment(request: Request, ref: GateRef): Promise<RequirePaymentResult> {
            const gate = await resolveGate(ref, request);
            const eligible = adapters.filter(adapter => gate.accepts(adapter.protocol));
            if (eligible.length === 0) {
                throw new ConfigurationError(
                    `Gate "${gate.name}" accepts [${gate.accept.join(', ')}] but no matching adapter is configured.`,
                );
            }

            const claimed = eligible.find(adapter => adapter.detect(request));
            if (claimed) {
                try {
                    const payment = await claimed.verifyAndSettle(gate, request);
                    payments.set(request, payment);
                    return {
                        payment,
                        status: 200,
                        withSettlement(response: Response): Response {
                            const headers = new Headers(response.headers);
                            for (const [name, value] of Object.entries(payment.settlementHeaders)) {
                                headers.set(name, value);
                            }
                            return new Response(response.body, {
                                headers,
                                status: response.status,
                                statusText: response.statusText,
                            });
                        },
                    };
                } catch (error) {
                    if (!(error instanceof InvalidProofError)) throw error;
                    const challenge = await buildChallenge(gate, request, eligible);
                    return {
                        challenge,
                        response: render402(challenge, {
                            accepts: challenge.accepts,
                            code: error.code,
                            ...(error.message !== error.code ? { detail: error.message } : {}),
                        }),
                        status: 402,
                    };
                }
            }

            const challenge = await buildChallenge(gate, request, eligible);
            return {
                challenge,
                response: render402(challenge, { accepts: challenge.accepts }),
                status: 402,
            };
        },
    };
}
