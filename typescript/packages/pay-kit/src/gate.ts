import { ConfigurationError, MixedCurrenciesError, ProtocolIncompatibleError } from './errors.js';
import type { Fee } from './fee.js';
import { Price } from './price.js';
import type { Protocol } from './protocol.js';

/**
 * A fee value: either a bare {@link Price}, or a price paired with an on-chain
 * `memo` describing what the transfer is for (e.g. `"platform fee"`). The memo
 * rides along on that recipient's split transfer.
 */
export type FeeSpec = Price | { readonly memo?: string; readonly price: Price };

/** Defaults a {@link Gate} inherits from the boot config when a field is omitted. */
export type GateDefaults = {
    /** Protocols accepted when the gate does not set `accept` explicitly. */
    readonly accept: readonly Protocol[];
    /** Recipient used when the gate does not set `payTo` explicitly. */
    readonly payTo: string;
};

/**
 * The settlement shape of a gate:
 * - `fixed` — charge a fixed amount up front (MPP `charge` / x402 `exact`),
 * - `usage` — authorize a ceiling and settle the metered amount afterwards (x402 `upto`),
 * - `subscription` — activate a recurring on-chain authorization on the first call (MPP `subscription`),
 * - `session` — open a payment channel and meter streamed deliveries, settling out-of-band (MPP `session`).
 *
 * Defaults to `fixed`. `subscription` and `session` are MPP-only.
 */
export type GateKind = 'fixed' | 'session' | 'subscription' | 'usage';

/** Metering config for a {@link GateKind} `session` gate (MPP `session`). */
export type SessionConfig = {
    /** Idle-close delay in ms — settle the channel this long after the last delivery. */
    readonly closeDelayMs?: number;
    /** Per-delivery price in base units (the streamed unit cost). */
    readonly unitPrice: bigint;
};

/** On-chain plan binding for a {@link GateKind} `subscription` gate (MPP `subscription`). */
export type SubscriptionConfig = {
    /** Number of `periodUnit`s per billing period (e.g. 30 days). */
    readonly periodCount: number;
    /** Billing period unit. The Solana profile supports `day` and `week`. */
    readonly periodUnit: 'day' | 'week';
    /** Base58 of the on-chain Plan PDA the subscription binds to. */
    readonly planId: string;
    /** Base58 of the puller pubkey that debits renewals (typically the operator). */
    readonly puller: string;
};

/** Parameters for {@link Gate.create}. */
export type GateParams = {
    /** Per-gate protocol override. Omit to inherit the config default. */
    readonly accept?: readonly Protocol[];
    /** Fixed charge, or — for a `usage` gate — the authorized maximum. */
    readonly amount: Price;
    readonly description?: string;
    /** Merchant correlation id (order id, invoice number) echoed in receipts. */
    readonly externalId?: string;
    /** Fees added to the customer's total, keyed by recipient address. Each value
     * is a {@link Price}, or `{ price, memo }` to label the transfer on-chain. */
    readonly feeOnTop?: Readonly<Record<string, FeeSpec>>;
    /** Fees taken out of `amount`, keyed by recipient address. Each value is a
     * {@link Price}, or `{ price, memo }` to label the transfer on-chain. */
    readonly feeWithin?: Readonly<Record<string, FeeSpec>>;
    /** `fixed` (default), `usage`, `subscription`, or `session`. */
    readonly kind?: GateKind;
    readonly name: string;
    /** Recipient of the base amount. Omit to inherit the operator recipient. */
    readonly payTo?: string;
    /** Metering config — required for (and only valid on) `session` gates. */
    readonly session?: SessionConfig;
    /** Plan binding — required for (and only valid on) `subscription` gates. */
    readonly subscription?: SubscriptionConfig;
};

/**
 * A priced unit of work attached to a route. Immutable and validated at
 * construction so misconfiguration fails at boot, not per request.
 *
 * @example
 * ```ts
 * const gate = Gate.create(
 *   { amount: usd('10.00'), feeWithin: { [PLATFORM]: usd('0.30') }, name: 'marketplace' },
 *   { accept: ['mpp'], payTo: SELLER },
 * );
 * gate.total();          // USD 10.00
 * gate.payout(SELLER);   // USD 9.70
 * gate.payout(PLATFORM); // USD 0.30
 * ```
 */
export class Gate {
    readonly accept: readonly Protocol[];
    readonly amount: Price;
    readonly description: string | undefined;
    readonly externalId: string | undefined;
    readonly fees: readonly Fee[];
    readonly kind: GateKind;
    readonly name: string;
    readonly payTo: string;
    /** Metering config for `session` gates; `undefined` otherwise. */
    readonly session: SessionConfig | undefined;
    /** Plan binding for `subscription` gates; `undefined` otherwise. */
    readonly subscription: SubscriptionConfig | undefined;

    private constructor(params: {
        accept: readonly Protocol[];
        amount: Price;
        description: string | undefined;
        externalId: string | undefined;
        fees: readonly Fee[];
        kind: GateKind;
        name: string;
        payTo: string;
        session: SessionConfig | undefined;
        subscription: SubscriptionConfig | undefined;
    }) {
        this.accept = Object.freeze([...params.accept]);
        this.amount = params.amount;
        this.description = params.description;
        this.externalId = params.externalId;
        this.fees = Object.freeze([...params.fees]);
        this.kind = params.kind;
        this.name = params.name;
        this.payTo = params.payTo;
        this.session = params.session ? Object.freeze({ ...params.session }) : undefined;
        this.subscription = params.subscription ? Object.freeze({ ...params.subscription }) : undefined;
        Object.freeze(this);
    }

    /**
     * Builds and validates a gate, resolving omitted fields from `defaults`.
     *
     * Validation rules (identical across the SDK family):
     * - fee currencies must match the amount currency,
     * - `feeWithin` fees must sum to less than the amount,
     * - fees with an explicit `accept` containing x402 fail
     *   ({@link ProtocolIncompatibleError}); with an inherited `accept` the
     *   gate silently narrows to MPP.
     *
     * @throws {ConfigurationError} on invalid amounts or fee sums.
     * @throws {MixedCurrenciesError} when a fee currency differs from the amount currency.
     * @throws {ProtocolIncompatibleError} when fees are combined with an explicit x402 accept.
     */
    static create(params: GateParams, defaults: GateDefaults): Gate {
        const kind = params.kind ?? 'fixed';
        const toFee = (recipient: string, spec: FeeSpec, feeKind: 'on_top' | 'within'): Fee => {
            const price = spec instanceof Price ? spec : spec.price;
            const memo = spec instanceof Price ? undefined : spec.memo;
            return { kind: feeKind, price, recipient, ...(memo ? { memo } : {}) };
        };
        const fees: Fee[] = [
            ...Object.entries(params.feeWithin ?? {}).map(([recipient, spec]) => toFee(recipient, spec, 'within')),
            ...Object.entries(params.feeOnTop ?? {}).map(([recipient, spec]) => toFee(recipient, spec, 'on_top')),
        ];

        if ((kind === 'usage' || kind === 'subscription' || kind === 'session') && fees.length > 0) {
            throw new ProtocolIncompatibleError(
                `Gate "${params.name}": ${kind} gates settle to a single recipient and cannot carry fees.`,
            );
        }

        const payTo = params.payTo ?? defaults.payTo;
        for (const fee of fees) {
            if (fee.price.currency !== params.amount.currency) {
                throw new MixedCurrenciesError(
                    `Gate "${params.name}": fee to ${fee.recipient} is denominated in ` +
                        `${fee.price.currency} but the amount is in ${params.amount.currency}.`,
                );
            }
            if (fee.recipient === payTo) {
                throw new ConfigurationError(
                    `Gate "${params.name}": fee recipient equals payTo. Fold the fee into the amount instead.`,
                );
            }
        }

        const withinTotal = fees
            .filter(fee => fee.kind === 'within')
            .reduce((sum, fee) => sum.plus(fee.price), params.amount.withAmount('0'));
        if (!params.amount.isGreaterThan(withinTotal)) {
            throw new ConfigurationError(
                `Gate "${params.name}": feeWithin total (${withinTotal.amount}) must be ` +
                    `less than the amount (${params.amount.amount}).`,
            );
        }

        let accept = params.accept ?? defaults.accept;
        if (kind === 'usage') {
            // The `upto` scheme exists only on x402; a usage gate is x402-only.
            if (params.accept && !params.accept.includes('x402')) {
                throw new ProtocolIncompatibleError(
                    `Gate "${params.name}": usage (upto) gates require the x402 protocol.`,
                );
            }
            accept = ['x402'];
        } else if (kind === 'subscription' || kind === 'session') {
            // `subscription` and `session` are MPP-only methods.
            if (params.accept && !params.accept.includes('mpp')) {
                throw new ProtocolIncompatibleError(`Gate "${params.name}": ${kind} gates require the mpp protocol.`);
            }
            if (kind === 'subscription' && !params.subscription) {
                throw new ConfigurationError(
                    `Gate "${params.name}": subscription gates require a "subscription" plan binding (planId, periodUnit, periodCount, puller).`,
                );
            }
            if (kind === 'session' && !params.session) {
                throw new ConfigurationError(
                    `Gate "${params.name}": session gates require a "session" config (unitPrice).`,
                );
            }
            accept = ['mpp'];
        } else if (fees.length > 0) {
            if (params.accept?.includes('x402')) {
                throw new ProtocolIncompatibleError(
                    `Gate "${params.name}": multi-recipient fees are not expressible in the ` +
                        `x402 exact scheme. Remove the explicit x402 accept or the fees.`,
                );
            }
            accept = accept.filter(protocol => protocol !== 'x402');
        }
        if (accept.length === 0) {
            throw new ConfigurationError(`Gate "${params.name}": accepts no protocols.`);
        }

        return new Gate({
            accept,
            amount: params.amount,
            description: params.description,
            externalId: params.externalId,
            fees,
            kind,
            name: params.name,
            payTo,
            session: params.session,
            subscription: params.subscription,
        });
    }

    /** Whether this gate accepts the given protocol. */
    accepts(protocol: Protocol): boolean {
        return this.accept.includes(protocol);
    }

    /** Fees added to the customer's total. */
    feeOnTop(): readonly Fee[] {
        return this.fees.filter(fee => fee.kind === 'on_top');
    }

    /** Fees taken out of the amount. */
    feeWithin(): readonly Fee[] {
        return this.fees.filter(fee => fee.kind === 'within');
    }

    /** Whether any fees are configured. */
    hasFees(): boolean {
        return this.fees.length > 0;
    }

    /** What `address` nets from one settlement, or `undefined` if it receives nothing. */
    payout(address: string): Price | undefined {
        const feeTotal = (fees: readonly Fee[]) =>
            fees.reduce((sum, fee) => sum.plus(fee.price), this.amount.withAmount('0'));
        if (address === this.payTo) {
            return this.amount.minus(feeTotal(this.feeWithin()));
        }
        const toAddress = this.fees.filter(fee => fee.recipient === address);
        return toAddress.length > 0 ? feeTotal(toAddress) : undefined;
    }

    /** The customer's total: amount plus all on-top fees. */
    total(): Price {
        return this.feeOnTop().reduce((sum, fee) => sum.plus(fee.price), this.amount);
    }
}
