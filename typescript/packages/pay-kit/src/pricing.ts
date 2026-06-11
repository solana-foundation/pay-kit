import type { PayKitConfig } from './config.js';
import { UnknownGateError } from './errors.js';
import { Gate, type GateDefaults, type GateParams } from './gate.js';
import { Price } from './price.js';

/** Gate parameters without a name (the catalogue key or inline context provides it). */
export type InlineGateParams = Omit<GateParams, 'name'>;

/**
 * A request-evaluated gate definition. Returns either a bare {@link Price}
 * (an anonymous gate at that price) or full gate parameters.
 */
export type GateResolver = (request: Request) => InlineGateParams | Price | Promise<InlineGateParams | Price>;

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
export function createPricing(
    config: PayKitConfig,
    definitions: Readonly<Record<string, GateResolver | InlineGateParams>>,
): Pricing {
    const defaults = gateDefaults(config);
    const gates = new Map<string, DynamicGate | Gate>();
    for (const [name, definition] of Object.entries(definitions)) {
        gates.set(
            name,
            typeof definition === 'function'
                ? new DynamicGate(name, definition, defaults)
                : Gate.create({ ...definition, name }, defaults),
        );
    }
    return new Pricing(gates);
}
