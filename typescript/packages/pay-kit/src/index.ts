/**
 * @solana/pay-kit — protocol-agnostic payment gating for HTTP services.
 *
 * The layer-1 PayKit surface (see docs/paykit-interface.md): one set of
 * nouns (Config, Operator, Signer, Price, Fee, Gate, Pricing, Payment,
 * Challenge), three request verbs (requirePayment / paid / payment), and a
 * protocol adapter seam that keeps payment protocols invisible to
 * application code.
 */

export type { ProtocolAdapter } from './adapter.js';
export { createMppAdapter } from './adapters/mpp.js';
export type { AcceptsEntry, Challenge } from './challenge.js';
export {
    configure,
    configureFromEnv,
    type ConfigureParams,
    type MppOptions,
    type Operator,
    type OperatorParams,
    type PayKitConfig,
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
export type { Fee, FeeKind } from './fee.js';
export { Gate, type GateDefaults, type GateParams } from './gate.js';
export { withPayment } from './handler.js';
export type { Payment } from './payment.js';
export {
    createPayKit,
    type GateRef,
    type PayKit,
    type PaymentDenied,
    type PaymentGranted,
    type RequirePaymentResult,
} from './paykit.js';
export { type Currency, eur, gbp, Price, type Stablecoin, STABLECOINS, usd } from './price.js';
export {
    createPricing,
    DynamicGate,
    gateDefaults,
    type GateResolver,
    type InlineGateParams,
    Pricing,
} from './pricing.js';
export { caip2, type Network, type NetworkSlug, toNetwork, type Protocol, toSolanaNetwork } from './protocol.js';
export { type KeychainSigner, type PayKitSigner, Signer } from './signer.js';
// Replay-protection stores (memory, Redis, Upstash, Cloudflare KV) come from mppx.
export { Store } from 'mppx';
