import type { PayKitConfig } from './config.js';
import { UnknownGateError } from './errors.js';
import { Gate, type GateDefaults, type GateParams, type SessionConfig, type SubscriptionConfig } from './gate.js';
import { Price } from './price.js';

/** Gate parameters without a name (the catalogue key or inline context provides it). */
export type InlineGateParams = Omit<GateParams, 'name'>;

/**
 * A usage-based (`upto`) gate definition: authorize up to `amount`, then settle
 * the metered amount the handler reports. Produced by {@link usage}.
 */
export type UsageGateParams = Omit<InlineGateParams, 'feeOnTop' | 'feeWithin'> & { readonly kind: 'usage' };

/**
 * A subscription gate definition: the first call activates a recurring on-chain
 * authorization against `subscription.planId`, then settles each period. MPP-only.
 * Produced by {@link subscription}.
 */
export type SubscriptionGateParams = Omit<InlineGateParams, 'feeOnTop' | 'feeWithin'> & {
    readonly kind: 'subscription';
    readonly subscription: SubscriptionConfig;
};

/**
 * A session gate definition: open a payment channel capped at `amount`, meter
 * streamed deliveries at `session.unitPrice`, and settle out-of-band. MPP-only.
 * Produced by {@link session}.
 */
export type SessionGateParams = Omit<InlineGateParams, 'feeOnTop' | 'feeWithin'> & {
    readonly kind: 'session';
    readonly session: SessionConfig;
};

/**
 * A request-evaluated gate definition. Returns either a bare {@link Price}
 * (an anonymous gate at that price) or full gate parameters.
 */
export type GateResolver = (request: Request) => InlineGateParams | Price | Promise<InlineGateParams | Price>;

/**
 * A pricing catalogue definition: one entry per gate name. A value is a bare
 * {@link Price} (a fixed charge at that price), full {@link InlineGateParams}
 * (fees, splits, protocol override), a {@link usage} gate, or a
 * {@link GateResolver} evaluated per request.
 */
export type PricingDef = Readonly<Record<string, GateResolver | InlineGateParams | Price>>;

/**
 * Declares a usage-based (`upto`) gate: the client authorizes up to `max`, the
 * handler reports actual consumption, and the gate settles that — never more
 * than `max` — refunding the rest. x402-only.
 *
 * @example
 * ```ts
 * pricing: { summarize: usage(usd('1.00')) }
 * ```
 *
 * @param max - The authorized ceiling
 * @param params - Optional description / externalId / payTo
 * @returns A usage gate definition
 */
export function usage(max: Price, params: Omit<UsageGateParams, 'amount' | 'kind'> = {}): UsageGateParams {
    return { ...params, amount: max, kind: 'usage' };
}

/**
 * Declares a subscription gate: the first request activates a recurring on-chain
 * authorization against `planId`, debiting `amount` per period; subsequent
 * periods are pulled by `puller`. MPP-only.
 *
 * @example
 * ```ts
 * pricing: {
 *   feed: subscription(usd('0.10'), { planId, periodUnit: 'day', periodCount: 1, puller: operator }),
 * }
 * ```
 *
 * @param amount - The per-period charge
 * @param config - Plan binding (planId, periodUnit, periodCount, puller) plus optional description / payTo
 * @returns A subscription gate definition
 */
export function subscription(
    amount: Price,
    config: Omit<SubscriptionGateParams, 'amount' | 'kind' | 'subscription'> & SubscriptionConfig,
): SubscriptionGateParams {
    const { periodCount, periodUnit, planId, puller, ...rest } = config;
    return { ...rest, amount, kind: 'subscription', subscription: { periodCount, periodUnit, planId, puller } };
}

/**
 * Declares a session gate: the client opens a payment channel capped at `cap`,
 * the server meters streamed deliveries at `unitPrice` each, and settlement runs
 * out-of-band when the channel idle-closes. MPP-only.
 *
 * @example
 * ```ts
 * pricing: { stream: session(usd('1.00'), { unitPrice: usd('0.0001') }) }
 * ```
 *
 * @param cap - The authorized channel ceiling
 * @param config - Per-delivery `unitPrice` plus optional `closeDelayMs` / description / payTo
 * @returns A session gate definition
 */
export function session(
    cap: Price,
    config: Omit<SessionGateParams, 'amount' | 'kind' | 'session'> & { closeDelayMs?: number; unitPrice: Price },
): SessionGateParams {
    const { closeDelayMs, unitPrice, ...rest } = config;
    return {
        ...rest,
        amount: cap,
        kind: 'session',
        session: { unitPrice: unitPrice.baseUnits(), ...(closeDelayMs !== undefined ? { closeDelayMs } : {}) },
    };
}

/** A named gate whose shape is computed per request. */
export class DynamicGate {
    readonly name: string;
    readonly #defaults: GateDefaults;
    readonly #resolver: GateResolver;

    constructor(name: string, resolver: GateResolver, defaults: GateDefaults) {
        this.name = name;
        this.#defaults = defaults;
        this.#resolver = resolver;
    }

    /** Materializes the gate for one request. */
    async resolve(request: Request): Promise<Gate> {
        const result = await this.#resolver(request);
        const params: InlineGateParams = result instanceof Price ? { amount: result } : result;
        return Gate.create({ ...params, name: this.name }, this.#defaults);
    }
}

/**
 * A named, boot-validated catalogue of gates.
 *
 * @example
 * ```ts
 * const pricing = createPricing(config, {
 *   marketplace: { amount: usd('10.00'), feeWithin: { [PLATFORM]: usd('0.30') }, payTo: SELLER },
 *   report: { amount: usd('0.10'), description: 'Premium report' },
 *   tiered: request => usd(new URL(request.url).searchParams.get('tier') === 'pro' ? '5.00' : '0.10'),
 * });
 * ```
 */
export class Pricing {
    readonly #gates: ReadonlyMap<string, DynamicGate | Gate>;

    constructor(gates: ReadonlyMap<string, DynamicGate | Gate>) {
        this.#gates = gates;
    }

    /**
     * Looks up a gate by name.
     *
     * @throws {UnknownGateError} when the name is not registered.
     */
    gate(name: string): DynamicGate | Gate {
        const gate = this.#gates.get(name);
        if (!gate) throw new UnknownGateError(name);
        return gate;
    }

    /** All registered gate names. */
    names(): readonly string[] {
        return [...this.#gates.keys()];
    }
}

/** Gate defaults derived from a boot config. */
export function gateDefaults(config: PayKitConfig): GateDefaults {
    return { accept: config.accept, payTo: config.operator.recipient };
}

/**
 * Builds a {@link Pricing} catalogue from gate definitions, resolving
 * defaults (recipient, accepted protocols) from the boot config. Static
 * definitions are validated immediately; resolver functions become
 * {@link DynamicGate}s evaluated per request.
 */
export function createPricing(config: PayKitConfig, definitions: PricingDef): Pricing {
    const defaults = gateDefaults(config);
    const gates = new Map<string, DynamicGate | Gate>();
    for (const [name, definition] of Object.entries(definitions)) {
        if (typeof definition === 'function') {
            gates.set(name, new DynamicGate(name, definition, defaults));
        } else {
            const params = definition instanceof Price ? { amount: definition } : definition;
            gates.set(name, Gate.create({ ...params, name }, defaults));
        }
    }
    return new Pricing(gates);
}
