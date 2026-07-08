/**
 * OpenAPI 3.1 discovery: a self-documenting `/openapi.json` describing a
 * server's priced routes. Each gated operation carries an `x-payment-info`
 * extension whose `offers[]` lists every way to pay (one per accepted
 * protocol/scheme), and the document root carries optional `x-service-info`.
 *
 * The extension shape mirrors mppx's discovery convention so the same tooling
 * reads it — augmented here so a single offer list spans both MPP (`charge`)
 * and x402 (`exact` / `upto`), which a multi-protocol PayKit server advertises.
 * Discovery is advisory; the runtime 402 challenge stays authoritative.
 */

/**
 * One way to pay for a route, in an operation's `x-payment-info.offers` list.
 * `intent` + `method` + `amount` are the fields required by the payment-discovery
 * draft (paymentauth.org/draft-payment-discovery-00); the rest are the spec's
 * optional fields plus pay-kit extras (`network`, `payTo`, `feePayer`, `scheme`)
 * that the runtime 402 challenge ultimately confirms.
 */
export type PaymentOffer = {
    /** Base-unit integer amount (max, for `upto`); `null` when unpriced. */
    readonly amount: string | null;
    /** Settlement coin symbol, e.g. `"USDC"`. */
    readonly currency?: string;
    /** Human-readable price, e.g. `"0.01 USDC"` (or `"up to 0.10 USDC"`). */
    readonly description?: string;
    /** Fee-payer / facilitator address that sponsors settlement, when the scheme has one. */
    readonly feePayer?: string;
    /** Payment intent (discovery-draft required): `"charge"` for one-shot, `"session"` for metered streams. */
    readonly intent: string;
    /** Payment method/rail (discovery-draft required): the protocol, e.g. `"x402"` or `"mpp"`. */
    readonly method: string;
    /** CAIP-2 network. */
    readonly network?: string;
    /** Recipient address. */
    readonly payTo?: string;
    /** On-chain Plan PDA — present on `subscription` offers. */
    readonly planId?: string;
    /** Scheme: `"exact"` / `"upto"` (x402) or `"charge"` / `"subscription"` (MPP). */
    readonly scheme?: string;
    /** Per-delivery price in base units — present on `session` offers. */
    readonly unitPrice?: string;
};

/** Document-root `x-service-info` extension: service-level (not per-payment) metadata. */
export type ServiceInfo = {
    readonly categories?: readonly string[];
    readonly docs?: { readonly apiReference?: string; readonly homepage?: string; readonly llms?: string };
};

/** A resolved route for {@link buildOpenApiDocument}. */
export type OpenApiRouteDoc = {
    readonly method: string;
    readonly offers: readonly PaymentOffer[] | null;
    readonly path: string;
    readonly requestBody?: Record<string, unknown>;
    readonly summary?: string;
};

/** `info` block of the generated document. */
export type OpenApiInfo = { readonly title?: string; readonly version?: string };

/**
 * Build an OpenAPI 3.1 discovery document from resolved priced routes.
 *
 * @param config - The document info, routes (with payment offers), and optional service info
 * @returns The OpenAPI document object
 */
export function buildOpenApiDocument(config: {
    info?: OpenApiInfo;
    routes: readonly OpenApiRouteDoc[];
    serviceInfo?: ServiceInfo;
}): Record<string, unknown> {
    const paths: Record<string, Record<string, unknown>> = {};

    for (const route of config.routes) {
        const method = route.method.toLowerCase();
        const operation: Record<string, unknown> = {
            responses: {
                ...(route.offers ? { '402': { description: 'Payment Required' } } : {}),
                '200': { description: 'Successful response' },
            },
        };
        if (route.offers) operation['x-payment-info'] = { offers: route.offers };
        if (route.summary) operation.summary = route.summary;
        if (route.requestBody) operation.requestBody = route.requestBody;

        (paths[route.path] ??= {})[method] = operation;
    }

    const doc: Record<string, unknown> = {
        info: { title: config.info?.title ?? 'API', version: config.info?.version ?? '1.0.0' },
        openapi: '3.1.0',
        paths,
    };
    if (config.serviceInfo) doc['x-service-info'] = config.serviceInfo;
    return doc;
}
