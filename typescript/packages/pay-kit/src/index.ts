/**
 * @solana/pay-kit — protocol-agnostic payment gating for HTTP services.
 *
 * One factory, one config object: `createPayKit({ network, operator, accept,
 * pricing })` returns an instance with the canonical verb trio
 * (`requirePayment` / `paid` / `payment`) and framework handlers
 * (`express` / `hono` / `fetch`). Gate names are inferred from `pricing`.
 * Payment protocols (x402, MPP) stay invisible to application code — the only
 * protocol knob is `accept`. See docs/paykit-interface.md.
 */

export type { ProtocolAdapter } from './adapter.js';
export { Charge } from './adapters/x402-upto.js';
export type { AcceptsEntry, Challenge } from './challenge.js';
export {
    configure,
    configureFromEnv,
    type ConfigureParams,
    type MppOptions,
    type Operator,
    type OperatorParams,
    type PayKitConfig,
    type X402Options,
} from './config.js';
export {
    ChallengeExpiredError,
    ConfigurationError,
    DemoSignerOnMainnetError,
    InvalidKeyError,
    InvalidProofError,
    MixedCurrenciesError,
    PayKitError,
    PaymentRequiredError,
    ProtocolIncompatibleError,
    ProtocolNotSupportedError,
    UnknownGateError,
} from './errors.js';
export { type ExpressRoutesApp, introspectExpressRoutes, type IntrospectedRoute } from './express-routes.js';
export type { Fee, FeeKind } from './fee.js';
export {
    type FeeSpec,
    Gate,
    type GateDefaults,
    type GateKind,
    type GateParams,
    type SessionConfig,
    type SubscriptionConfig,
} from './gate.js';
export {
    buildOpenApiDocument,
    type OpenApiInfo,
    type OpenApiRouteDoc,
    type PaymentOffer,
    type ServiceInfo,
} from './openapi.js';
export type { Payment } from './payment.js';
export {
    createPayKit,
    type CreatePayKitOptions,
    type ExpressMiddleware,
    type FetchHandler,
    type GateName,
    type GateRef,
    type HonoMiddleware,
    type OpenApiOptions,
    type OpenApiRoute,
    type PayKit,
    type PaymentDenied,
    type PaymentGranted,
    type PaymentRespond,
    type RequirePaymentResult,
    type SessionRouteHandlers,
    type SessionRouteRequest,
} from './paykit.js';
export { type Currency, eur, gbp, Price, type Stablecoin, STABLECOINS, usd } from './price.js';
export {
    createPricing,
    DynamicGate,
    gateDefaults,
    type GateResolver,
    type InlineGateParams,
    Pricing,
    type PricingDef,
    session,
    type SessionGateParams,
    subscription,
    type SubscriptionGateParams,
    usage,
    type UsageGateParams,
} from './pricing.js';
export { caip2, type Network, type NetworkSlug, toNetwork, type Protocol, toSolanaNetwork } from './protocol.js';
export { type KeychainSigner, type PayKitSigner, Signer } from './signer.js';
// Replay-protection stores (memory, Redis, Upstash, Cloudflare KV) come from mppx.
export { Store } from 'mppx';
