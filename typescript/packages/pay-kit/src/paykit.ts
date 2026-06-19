import type { ProtocolAdapter } from './adapter.js';
import { createMppAdapter } from './adapters/mpp.js';
import { createSessionEngine, type SessionEngine } from './adapters/mpp-session.js';
import { createX402ExactAdapter } from './adapters/x402.js';
import { Charge, X402Upto } from './adapters/x402-upto.js';
import type { AcceptsEntry, Challenge } from './challenge.js';
import { configure, type ConfigureParams, type PayKitConfig } from './config.js';
import { ConfigurationError, InvalidProofError } from './errors.js';
import { type ExpressRoutesApp, GATE_METADATA, introspectExpressRoutes } from './express-routes.js';
import { Gate } from './gate.js';
import {
    type NextFunction,
    type NodeRequest,
    type NodeResponse,
    sendResponse,
    toWebRequest,
    type WebContext,
    type WebNext,
} from './http.js';
import {
    buildOpenApiDocument,
    type OpenApiInfo,
    type OpenApiRouteDoc,
    type PaymentOffer,
    type ServiceInfo,
} from './openapi.js';
import type { Payment } from './payment.js';
import { Price } from './price.js';
import {
    createPricing,
    DynamicGate,
    gateDefaults,
    type GateResolver,
    type InlineGateParams,
    type PricingDef,
} from './pricing.js';
import { caip2 } from './protocol.js';

/**
 * A gate name from the configured pricing catalogue. With a concrete `pricing`
 * literal this is the union of its keys, so names autocomplete and a typo is a
 * compile error; with no pricing it widens to `string`.
 */
export type GateName<P extends PricingDef> = string & keyof P;

/**
 * Anything that names a gate: a catalogue name (typed against `pricing`), a
 * {@link Gate}, a bare {@link Price} (anonymous inline gate), or a per-request
 * resolver.
 */
export type GateRef<P extends PricingDef = PricingDef> = DynamicGate | Gate | GateName<P> | GateResolver | Price;

/** A priced route to advertise in the OpenAPI discovery document. */
export type OpenApiRoute<P extends PricingDef = PricingDef> = {
    readonly gate: GateRef<P>;
    readonly method: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
    readonly path: string;
    readonly requestBody?: Record<string, unknown>;
    readonly summary?: string;
};

/** Options for {@link PayKit.openapi}. */
export type OpenApiOptions = { readonly info?: OpenApiInfo; readonly serviceInfo?: ServiceInfo };

/** The request did not carry a valid payment; respond with `response`. */
export type PaymentDenied = {
    readonly challenge: Challenge;
    readonly response: Response;
    readonly status: 402;
};

/**
 * The payment verified; reply through `withSettlement`. For `usage` gates the
 * `charge` meter records consumption and settlement runs when `withSettlement`
 * (or `settle`) is called; for fixed gates settlement already happened.
 */
export type PaymentGranted = {
    /** Usage meter — present only for `usage` (upto) gates. */
    readonly charge: Charge | undefined;
    readonly payment: Payment;
    /** Runs settlement (for usage gates) and returns the headers to merge. Memoized. */
    readonly settle: () => Promise<Readonly<Record<string, string>>>;
    readonly status: 200;
    /** Returns `response` with the settlement headers merged in (settles usage gates). */
    readonly withSettlement: (response: Response) => Promise<Response>;
};

/**
 * Send `respond` verbatim — a protocol owns the response for an unpaid request
 * (e.g. MPP's HTML payment page or its service worker). Status comes from the
 * Response itself.
 */
export type PaymentRespond = {
    readonly respond: Response;
};

/** Result of {@link PayKit.requirePayment}. */
export type RequirePaymentResult = PaymentDenied | PaymentGranted | PaymentRespond;

/** Express/Connect-style middleware returned by {@link PayKit.express}. */
export type ExpressMiddleware = (req: NodeRequest, res: NodeResponse, next: NextFunction) => Promise<void>;

/** Hono-style middleware returned by {@link PayKit.hono}. */
export type HonoMiddleware = (c: WebContext, next: WebNext) => Promise<Response | undefined>;

/** A fetch-style route handler wrapped by {@link PayKit.fetch}. */
export type FetchHandler = (request: Request, payment: Payment) => Promise<Response> | Response;

/** An Express request as seen by the session side-channel handlers (body/params parsed by Express). */
export type SessionRouteRequest = NodeRequest & {
    readonly body?: unknown;
    readonly params?: Readonly<Record<string, string | undefined>>;
};

/**
 * The session side-channel + receipt handlers for a `session` gate, returned by
 * {@link PayKit.sessionRoutes}. Mount them explicitly (mppx-consistent — pay-kit
 * does not auto-mount):
 * ```ts
 * const s = pay.sessionRoutes('stream');
 * app.post('/__402/session/deliveries', s.deliveries);
 * app.post('/__402/session/commit', s.commit);
 * app.get('/sessions/receipt/:channelId', s.receipt);
 * ```
 */
export type SessionRouteHandlers = {
    readonly commit: (req: SessionRouteRequest, res: NodeResponse) => Promise<void>;
    readonly deliveries: (req: SessionRouteRequest, res: NodeResponse) => Promise<void>;
    readonly receipt: (req: SessionRouteRequest, res: NodeResponse) => Promise<void>;
    /**
     * The resource-URL voucher-commit handler: the SessionFetchClient re-POSTs
     * each signed voucher (in the `Authorization` credential) to the URL it
     * opened against. Mount it there. Kept off the gated route so it isn't
     * advertised as a separate endpoint in discovery.
     */
    readonly voucher: (req: SessionRouteRequest, res: NodeResponse) => Promise<void>;
};

/**
 * The PayKit server instance: the canonical verb trio plus framework handlers,
 * over web-standard `Request`/`Response`. Created by {@link createPayKit}.
 */
export type PayKit<P extends PricingDef = PricingDef> = {
    /** Whether `request` carries a usage meter for the current route (usage gates only). */
    readonly charge: (request: object) => Charge | undefined;
    readonly config: PayKitConfig;
    /** Express / Connect / Polka middleware gating downstream handlers on `gate`. */
    readonly express: (gate: GateRef<P>) => ExpressMiddleware;
    /** Wrap a fetch-style handler (Workers / Bun / Deno / Next route handlers). */
    readonly fetch: (gate: GateRef<P>, handler: FetchHandler) => (request: Request) => Promise<Response>;
    /** Hono middleware gating downstream handlers on `gate`. */
    readonly hono: (gate: GateRef<P>) => HonoMiddleware;
    /** Build an OpenAPI 3.1 discovery document (`x-payment-info` per route) for the given priced routes. */
    readonly openapi: (
        routes: readonly OpenApiRoute<P>[],
        options?: OpenApiOptions,
    ) => Promise<Record<string, unknown>>;
    /** Like {@link openapi}, but discovers the routes by introspecting a mounted Express app. */
    readonly openapiFromExpress: (app: ExpressRoutesApp, options?: OpenApiOptions) => Promise<Record<string, unknown>>;
    /** Whether `request` already carries a verified payment (optionally for a specific gate). */
    readonly paid: (request: object, gate?: GateName<P>) => boolean;
    /** The verified payment on `request`, if any. */
    readonly payment: (request: object) => Payment | undefined;
    /** Verify-or-deny: settles a credential (or opens a usage channel) or produces the 402 challenge. */
    readonly requirePayment: (request: Request, gate: GateRef<P>) => Promise<RequirePaymentResult>;
    /** The side-channel + receipt handlers for a `session` gate, for the app to mount. */
    readonly sessionRoutes: (gate: Gate | GateName<P>) => SessionRouteHandlers;
};

/** Options for {@link createPayKit}: the boot config plus pricing and adapter overrides. */
export type CreatePayKitOptions<P extends PricingDef> = ConfigureParams & {
    /** Protocol adapters; defaults are derived from `accept`. */
    readonly adapters?: readonly ProtocolAdapter[];
    /** A pre-built, frozen config — skips the internal {@link configure} call. */
    readonly config?: PayKitConfig;
    /** The gate catalogue, inline. Gate names become typed on the returned instance. */
    readonly pricing?: P;
};

/**
 * Creates a PayKit instance from a single config object: network + operator +
 * accepted protocols + the inline `pricing` catalogue. Gate names are inferred
 * from `pricing`, so `pay.express('report')` autocompletes and a typo is a
 * compile error.
 *
 * @example
 * ```ts
 * const pay = await createPayKit({
 *   network: 'devnet',
 *   operator: { signer: await Signer.env('OPERATOR_KEY'), recipient: MERCHANT },
 *   pricing: {
 *     report: usd('0.10'),
 *     api: { amount: usd('0.001'), accept: ['x402'] },
 *     summarize: usage(usd('1.00')),
 *   },
 * });
 *
 * app.get('/report', pay.express('report'), (_req, res) => res.json({ ok: true }));
 * ```
 *
 * @param options - Boot config + `pricing` + optional adapter/config overrides
 * @returns The PayKit instance
 */
export async function createPayKit<const P extends PricingDef = PricingDef>(
    options: CreatePayKitOptions<P> = {},
): Promise<PayKit<P>> {
    const { adapters: adapterOverride, config: prebuilt, pricing: pricingDef, ...configureParams } = options;
    const config = prebuilt ?? (await configure(configureParams));

    const adapters =
        adapterOverride ??
        config.accept.map(protocol => {
            // configure() already rejects protocols without a shipped adapter.
            if (protocol === 'mpp') return createMppAdapter(config);
            if (protocol === 'x402') return createX402ExactAdapter(config);
            throw new ConfigurationError(`No adapter for protocol "${String(protocol)}".`);
        });
    const pricing = pricingDef ? createPricing(config, pricingDef) : undefined;
    const upto = config.accept.includes('x402') ? new X402Upto(config) : undefined;
    const defaults = gateDefaults(config);

    const payments = new WeakMap<object, Payment>();
    const charges = new WeakMap<object, Charge>();
    // Usage (upto) channel IDs currently being served — guards against a
    // concurrent replay of the same authorization serving the resource twice
    // for one deposit. Acquired after verify, released when settle completes.
    const inFlightUptoChannels = new Set<string>();
    // One session engine per session gate (shared store across its routes).
    const sessionEngines = new Map<string, SessionEngine>();

    function sessionEngineFor(gate: Gate): SessionEngine {
        let engine = sessionEngines.get(gate.name);
        if (!engine) {
            engine = createSessionEngine(config, gate);
            sessionEngines.set(gate.name, engine);
        }
        return engine;
    }

    /** Resolve a gate reference without a request — for mount-time use (session routes). */
    function resolveStaticGate(ref: Gate | GateName<P>): Gate {
        if (ref instanceof Gate) return ref;
        if (!pricing) {
            throw new ConfigurationError(
                `Gate "${ref}" referenced by name but no pricing catalogue was passed to createPayKit().`,
            );
        }
        const gate = pricing.gate(ref);
        if (gate instanceof DynamicGate) {
            throw new ConfigurationError(`Gate "${ref}": session gates cannot be request-resolved (dynamic).`);
        }
        return gate;
    }

    async function resolveGate(ref: GateRef<P>, request: Request): Promise<Gate> {
        if (ref instanceof Gate) return ref;
        if (ref instanceof DynamicGate) return await ref.resolve(request);
        if (ref instanceof Price) return Gate.create({ amount: ref, name: 'inline' }, defaults);
        if (typeof ref === 'string') {
            if (!pricing) {
                throw new ConfigurationError(
                    `Gate "${ref}" referenced by name but no pricing catalogue was passed to createPayKit().`,
                );
            }
            const gate = pricing.gate(ref);
            return gate instanceof DynamicGate ? await gate.resolve(request) : gate;
        }
        const result = await ref(request);
        const params: InlineGateParams = result instanceof Price ? { amount: result } : result;
        return Gate.create({ ...params, name: 'inline' }, defaults);
    }

    function render402(challenge: Challenge, body: Record<string, unknown>): Response {
        return new Response(JSON.stringify(body), {
            headers: { ...challenge.headers, 'content-type': 'application/json' },
            status: 402,
        });
    }

    function granted(
        payment: Payment,
        settle: () => Promise<Readonly<Record<string, string>>>,
        charge?: Charge,
    ): PaymentGranted {
        return {
            charge,
            payment,
            settle,
            status: 200,
            async withSettlement(response: Response): Promise<Response> {
                const headers = new Headers(response.headers);
                for (const [name, value] of Object.entries(await settle())) headers.set(name, value);
                return new Response(response.body, {
                    headers,
                    status: response.status,
                    statusText: response.statusText,
                });
            },
        };
    }

    async function requireFixed(gate: Gate, request: Request): Promise<RequirePaymentResult> {
        const eligible = adapters.filter(adapter => gate.accepts(adapter.protocol));
        if (eligible.length === 0) {
            throw new ConfigurationError(
                `Gate "${gate.name}" accepts [${gate.accept.join(', ')}] but no matching adapter is configured.`,
            );
        }

        const buildChallenge = async (): Promise<Challenge> => {
            const headers: Record<string, string> = {};
            const accepts: AcceptsEntry[] = [];
            for (const adapter of eligible) {
                accepts.push(await adapter.acceptsEntry(gate, request));
                Object.assign(headers, await adapter.challengeHeaders(gate, request));
            }
            return { accepts, headers, resource: new URL(request.url).pathname };
        };

        // A browser (`Accept: text/html`) or the service-worker request should
        // get the protocol's own response (MPP's interactive payment page +
        // worker) rather than the JSON 402 — for both an unpaid request and a
        // rejected one (re-render the page so the user can retry). API clients
        // (no `text/html`, no worker param) keep the combined JSON 402 that
        // advertises every accepted protocol.
        const htmlRespond = async (): Promise<PaymentRespond | undefined> => {
            const url = new URL(request.url);
            const wantsHtml = (request.headers.get('accept') ?? '').includes('text/html');
            const isWorker = url.searchParams.has('__mppx_worker') || url.searchParams.has('__mpp_worker');
            if (!wantsHtml && !isWorker) return undefined;
            for (const adapter of eligible) {
                const respond = await adapter.respond?.(gate, request);
                if (respond) return { respond };
            }
            return undefined;
        };

        const claimed = eligible.find(adapter => adapter.detect(request));
        if (!claimed) {
            const html = await htmlRespond();
            if (html) return html;
            const challenge = await buildChallenge();
            return { challenge, response: render402(challenge, { accepts: challenge.accepts }), status: 402 };
        }

        try {
            const payment = await claimed.verifyAndSettle(gate, request);
            payments.set(request, payment);
            return granted(payment, () => Promise.resolve(payment.settlementHeaders));
        } catch (error) {
            if (!(error instanceof InvalidProofError)) throw error;
            // Verification failed — re-render the HTML payment page for browsers
            // (retry-friendly), JSON for API clients.
            const html = await htmlRespond();
            if (html) return html;
            const challenge = await buildChallenge();
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

    async function requireUsage(gate: Gate, request: Request): Promise<RequirePaymentResult> {
        if (!upto) {
            throw new ConfigurationError(`Usage gate "${gate.name}" requires x402 in accept.`);
        }

        const usageChallenge = async (error?: InvalidProofError): Promise<PaymentDenied> => {
            const accepts: AcceptsEntry[] = upto.accepts(gate.amount).map(req => ({ ...req, protocol: 'x402' }));
            const challenge: Challenge = {
                accepts,
                headers: await upto.challengeHeaders(gate.amount, request),
                resource: new URL(request.url).pathname,
            };
            return {
                challenge,
                response: render402(challenge, {
                    accepts,
                    ...(error
                        ? { code: error.code, ...(error.message !== error.code ? { detail: error.message } : {}) }
                        : {}),
                }),
                status: 402,
            };
        };

        if (!upto.detect(request)) return await usageChallenge();

        let verified;
        try {
            verified = await upto.verifyOpen(request, gate.amount);
        } catch (error) {
            if (error instanceof InvalidProofError) return await usageChallenge(error);
            throw error;
        }

        // In-flight dedup: reject a concurrent request bearing the same channel
        // authorization before its handler runs, so a replayed PAYMENT-SIGNATURE
        // can't serve the (expensive, metered) resource twice for one deposit.
        // has()+add() are synchronous — no await between — so the check is atomic
        // under the single-threaded event loop. Released when settle completes.
        const channelId = (verified.payload.payload as { channelId?: string }).channelId;
        if (channelId !== undefined) {
            if (inFlightUptoChannels.has(channelId)) {
                return await usageChallenge(
                    new InvalidProofError('upto_channel_in_flight', 'channel already being served'),
                );
            }
            inFlightUptoChannels.add(channelId);
        }

        const meter = new Charge(verified.maxBaseUnits);
        charges.set(request, meter);
        const provisional: Payment = {
            gateName: gate.name,
            payer: verified.payer || undefined,
            protocol: 'x402',
            raw: undefined,
            scheme: 'upto',
            settlementHeaders: {},
            transaction: '',
        };
        payments.set(request, provisional);

        // Memoize the in-flight Promise (not its resolved value) so concurrent
        // callers — e.g. `Promise.all([result.settle(), result.withSettlement(r)])`,
        // both reachable from the public PaymentGranted API — share one settle
        // and `upto.settle()` broadcasts exactly once.
        let settlePromise: Promise<Readonly<Record<string, string>>> | undefined;
        const settle = (): Promise<Readonly<Record<string, string>>> =>
            (settlePromise ??= (async () => {
                try {
                    const result = await upto.settle(verified, meter.settledBaseUnits());
                    payments.set(request, { ...provisional, transaction: result.transaction });
                    return result.settlementHeaders;
                } finally {
                    if (channelId !== undefined) inFlightUptoChannels.delete(channelId);
                }
            })());

        return granted(provisional, settle, meter);
    }

    /** Settlement headers a session receipt-sealer carries (the channel-open receipt). */
    const SESSION_RECEIPT_HEADERS = ['payment-receipt', 'x-payment-settlement-signature'];

    async function requireSession(gate: Gate, request: Request): Promise<RequirePaymentResult> {
        const engine = sessionEngineFor(gate);
        const result = await engine.handler(request);
        if (result.status === 402) {
            return {
                challenge: { accepts: [], headers: {}, resource: new URL(request.url).pathname },
                response: result.challenge,
                status: 402,
            };
        }
        // The channel opened. Lift the open-receipt headers onto the response, but
        // do NOT settle here — session settlement is out-of-band (idle-close
        // watchdog + the `/sessions/receipt/:id` poll), and the handler may stream.
        const sealed = result.withReceipt(new Response(null));
        const settlementHeaders: Record<string, string> = {};
        for (const name of SESSION_RECEIPT_HEADERS) {
            const value = sealed.headers.get(name);
            if (value) settlementHeaders[name] = value;
        }
        const payment: Payment = {
            gateName: gate.name,
            payer: undefined,
            protocol: 'mpp',
            raw: request.headers.get('authorization') ?? undefined,
            scheme: 'session',
            settlementHeaders,
            transaction: '',
        };
        payments.set(request, payment);
        return granted(payment, () => Promise.resolve(settlementHeaders));
    }

    /** Settlement coin for a gate (its explicit preference, else the config default). */
    const coinFor = (gate: Gate): string => gate.amount.primaryCoin() ?? config.stablecoins[0] ?? 'USDC';

    /**
     * The discovery `intent` for a gate kind. `subscription` and `session` are
     * first-class intents (the UI keys its nav off these); `fixed` and `usage`
     * are both one-shot charges from the discovery perspective.
     */
    const intentFor = (gate: Gate): string =>
        gate.kind === 'subscription' ? 'subscription' : gate.kind === 'session' ? 'session' : 'charge';

    /** The discovery offers for a gate — one per accepted protocol/scheme. */
    async function offersForGate(gate: Gate, request: Request): Promise<PaymentOffer[]> {
        const coin = coinFor(gate);
        const intent = intentFor(gate);
        const toOffer = (entry: AcceptsEntry, max: boolean): PaymentOffer => {
            const extra = (entry.extra ?? {}) as { facilitator?: unknown; feePayer?: unknown };
            const feePayer = extra.feePayer ?? extra.facilitator ?? entry.feePayer;
            return {
                amount: entry.amount,
                currency: typeof entry.currency === 'string' ? entry.currency : coin,
                description: `${max ? 'up to ' : ''}${gate.total().amount} ${coin}`,
                ...(typeof feePayer === 'string' ? { feePayer } : {}),
                intent,
                method: entry.protocol,
                network: entry.network,
                payTo: entry.payTo,
                scheme: entry.scheme,
                ...(gate.subscription ? { planId: gate.subscription.planId } : {}),
            };
        };

        if (gate.kind === 'usage') {
            return upto ? upto.accepts(gate.amount).map(req => toOffer({ ...req, protocol: 'x402' }, true)) : [];
        }
        if (gate.kind === 'session') {
            // Session is MPP-only and streams; advertise the ceiling + per-delivery price directly.
            return [
                {
                    amount: gate.amount.baseUnits().toString(),
                    currency: coin,
                    description: `up to ${gate.total().amount} ${coin}`,
                    intent,
                    method: 'mpp',
                    network: caip2(config.network),
                    payTo: gate.payTo,
                    scheme: 'session',
                    ...(gate.session ? { unitPrice: gate.session.unitPrice.toString() } : {}),
                },
            ];
        }
        const eligible = adapters.filter(adapter => gate.accepts(adapter.protocol));
        return await Promise.all(
            eligible.map(async adapter => toOffer(await adapter.acceptsEntry(gate, request), false)),
        );
    }

    /** Build the OpenAPI document from a set of (method, path, gate) routes. */
    async function openapiDoc(
        routes: readonly {
            gate: unknown;
            method: string;
            path: string;
            requestBody?: Record<string, unknown>;
            summary?: string;
        }[],
        options?: OpenApiOptions,
    ): Promise<Record<string, unknown>> {
        const request = new Request('http://localhost/');
        const docRoutes: OpenApiRouteDoc[] = [];
        for (const route of routes) {
            const gate = await resolveGate(route.gate as GateRef<P>, request);
            docRoutes.push({
                method: route.method,
                offers: await offersForGate(gate, request),
                path: route.path,
                summary: route.summary ?? gate.description,
                ...(route.requestBody ? { requestBody: route.requestBody } : {}),
            });
        }
        return buildOpenApiDocument({ info: options?.info, routes: docRoutes, serviceInfo: options?.serviceInfo });
    }

    const instance: PayKit<P> = {
        charge(request: object): Charge | undefined {
            return charges.get(request);
        },

        config,

        express(gate: GateRef<P>): ExpressMiddleware {
            const middleware: ExpressMiddleware = async (req, res, next) => {
                let result: RequirePaymentResult;
                try {
                    result = await instance.requirePayment(toWebRequest(req), gate);
                } catch (error) {
                    next(error);
                    return;
                }
                if ('respond' in result) {
                    await sendResponse(res, result.respond);
                    return;
                }
                if (result.status === 402) {
                    await sendResponse(res, result.response);
                    return;
                }
                payments.set(req, result.payment);
                if (result.charge) charges.set(req, result.charge);

                if (!result.charge) {
                    // Fixed gate: settlement already happened; set headers, then run the handler.
                    for (const [name, value] of Object.entries(await result.settle())) res.setHeader(name, value);
                    next();
                    return;
                }
                await runBufferedSettle(res, next, result);
            };
            // Tag the middleware so `openapiFromExpress` can recover the gate.
            return Object.assign(middleware, { [GATE_METADATA]: gate });
        },

        fetch(gate: GateRef<P>, handler: FetchHandler): (request: Request) => Promise<Response> {
            return async request => {
                const result = await instance.requirePayment(request, gate);
                if ('respond' in result) return result.respond;
                if (result.status === 402) return result.response;
                let response: Response;
                try {
                    response = await handler(request, result.payment);
                } catch (error) {
                    // Finalize the upto channel even if the handler threw —
                    // verifyOpen already escrowed the ceiling on-chain (meter is
                    // 0, so this refunds). Best-effort; re-throw the original error.
                    try {
                        await result.settle();
                    } catch {
                        /* swallow settle failure; the handler error is what matters */
                    }
                    throw error;
                }
                return await result.withSettlement(response);
            };
        },

        hono(gate: GateRef<P>): HonoMiddleware {
            return async (c, next) => {
                const result = await instance.requirePayment(c.req.raw, gate);
                if ('respond' in result) return result.respond;
                if (result.status === 402) return result.response;
                try {
                    await next();
                } finally {
                    // Settle even if the handler threw: for usage (upto) gates
                    // `verifyOpen` already escrowed the ceiling on-chain, so the
                    // channel must be finalized regardless of the handler outcome.
                    // Best-effort — a transient settle (RPC) failure must not mask
                    // the handler's response (success) or its error (throw).
                    try {
                        for (const [name, value] of Object.entries(await result.settle()))
                            c.res.headers.set(name, value);
                    } catch {
                        /* swallow settle failure; preserve the handler outcome */
                    }
                }
                return undefined;
            };
        },

        openapi(routes, options): Promise<Record<string, unknown>> {
            return openapiDoc(routes, options);
        },

        openapiFromExpress(app: ExpressRoutesApp, options?: OpenApiOptions): Promise<Record<string, unknown>> {
            return openapiDoc(introspectExpressRoutes(app), options);
        },

        paid(request: object, gate?: GateName<P>): boolean {
            const payment = payments.get(request);
            return payment !== undefined && (gate === undefined || payment.gateName === gate);
        },

        payment(request: object): Payment | undefined {
            return payments.get(request);
        },

        async requirePayment(request: Request, ref: GateRef<P>): Promise<RequirePaymentResult> {
            const gate = await resolveGate(ref, request);
            if (gate.kind === 'usage') return await requireUsage(gate, request);
            if (gate.kind === 'session') return await requireSession(gate, request);
            return await requireFixed(gate, request);
        },

        sessionRoutes(gate: Gate | GateName<P>): SessionRouteHandlers {
            const engine = sessionEngineFor(resolveStaticGate(gate));
            // Express has parsed the JSON body; the side-channel handlers read it,
            // so rebuild the web Request with that body (toWebRequest is headers-only).
            const withBody = (req: SessionRouteRequest): Request => {
                const base = toWebRequest(req);
                return req.body === undefined
                    ? base
                    : new Request(base, { body: JSON.stringify(req.body), method: base.method });
            };
            const json = (res: NodeResponse, status: number, body: unknown): void => {
                res.statusCode = status;
                res.setHeader('content-type', 'application/json');
                res.end(JSON.stringify(body));
            };
            return {
                async commit(req, res) {
                    await sendResponse(res, await engine.commit(withBody(req)));
                },
                async deliveries(req, res) {
                    await sendResponse(res, await engine.deliveries(withBody(req)));
                },
                async receipt(req, res) {
                    const channelId = req.params?.channelId;
                    if (typeof channelId !== 'string' || channelId.length === 0) {
                        json(res, 400, { error: 'invalid-channel-id' });
                        return;
                    }
                    const state = await engine.receipt(channelId);
                    if (!state) {
                        json(res, 404, { error: 'channel-not-found' });
                        return;
                    }
                    json(res, 200, state);
                },
                async voucher(req, res) {
                    // The voucher rides the Authorization credential (header), so the
                    // headers-only web request is enough for the session method to apply it.
                    const result = await engine.handler(toWebRequest(req));
                    if (result.status === 402) {
                        await sendResponse(res, result.challenge);
                        return;
                    }
                    const body = (req.body ?? {}) as { amount?: string; deliveryId?: string };
                    const ack = Response.json({
                        amount: body.amount ?? '0',
                        deliveryId: body.deliveryId ?? '',
                        status: 'committed',
                    });
                    await sendResponse(res, result.withReceipt(ack));
                },
            };
        },
    };

    return instance;
}

/**
 * Run an Express handler with settle-after-response: buffer every commit path,
 * run the handler, settle the metered amount, then replay — so the settlement
 * header lands on the reply. Mirrors the x402 metered middleware.
 */
async function runBufferedSettle(res: NodeResponse, next: NextFunction, result: PaymentGranted): Promise<void> {
    const originalWriteHead = res.writeHead.bind(res);
    const originalWrite = res.write.bind(res);
    const originalEnd = res.end.bind(res);
    type BufferedCall = ['end', unknown[]] | ['write', unknown[]] | ['writeHead', unknown[]];
    let bufferedCalls: BufferedCall[] = [];
    let settled = false;
    let signalEnd: () => void = () => {};
    const ended = new Promise<void>(resolve => {
        signalEnd = resolve;
    });

    res.writeHead = function (...args: unknown[]) {
        if (!settled) {
            bufferedCalls.push(['writeHead', args]);
            return res;
        }
        return (originalWriteHead as (...a: unknown[]) => NodeResponse)(...args);
    } as typeof res.writeHead;
    res.write = function (...args: unknown[]) {
        if (!settled) {
            bufferedCalls.push(['write', args]);
            return true;
        }
        return (originalWrite as (...a: unknown[]) => boolean)(...args);
    } as typeof res.write;
    res.end = function (...args: unknown[]) {
        if (!settled) {
            bufferedCalls.push(['end', args]);
            signalEnd();
            return res;
        }
        return (originalEnd as (...a: unknown[]) => NodeResponse)(...args);
    } as typeof res.end;

    const restoreAndReplay = () => {
        settled = true;
        res.writeHead = originalWriteHead;
        res.write = originalWrite;
        res.end = originalEnd;
        for (const [method, args] of bufferedCalls) {
            if (method === 'writeHead') (originalWriteHead as (...a: unknown[]) => unknown)(...args);
            else if (method === 'write') (originalWrite as (...a: unknown[]) => unknown)(...args);
            else (originalEnd as (...a: unknown[]) => unknown)(...args);
        }
        bufferedCalls = [];
    };

    try {
        next();
    } catch (error) {
        restoreAndReplay();
        // Finalize the channel even on a synchronous handler throw: for usage
        // (upto) gates `verifyOpen` already escrowed the ceiling on-chain, so
        // skipping settle would leave it open. The meter is 0 here, so this
        // refunds. Best-effort — forward the original handler error regardless.
        try {
            await result.settle();
        } catch {
            /* swallow settle failure; the handler error is what matters */
        }
        next(error);
        return;
    }

    await ended;

    try {
        // Settle even on a handler error: the meter is 0 unless the handler
        // reported usage, so a failed request finalizes the channel and refunds.
        for (const [name, value] of Object.entries(await result.settle())) res.setHeader(name, value);
    } catch {
        settled = true;
        res.writeHead = originalWriteHead;
        res.write = originalWrite;
        res.end = originalEnd;
        bufferedCalls = [];
        res.statusCode = 402;
        originalEnd();
        return;
    }
    restoreAndReplay();
}
