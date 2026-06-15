import { ConfigurationError, MixedCurrenciesError, ProtocolIncompatibleError } from './errors.js';
import type { Fee } from './fee.js';
import type { Price } from './price.js';
import type { Protocol } from './protocol.js';

/** Defaults a {@link Gate} inherits from the boot config when a field is omitted. */
export type GateDefaults = {
    /** Protocols accepted when the gate does not set `accept` explicitly. */
    readonly accept: readonly Protocol[];
    /** Recipient used when the gate does not set `payTo` explicitly. */
    readonly payTo: string;
};

/** Parameters for {@link Gate.create}. */
export type GateParams = {
    /** Per-gate protocol override. Omit to inherit the config default. */
    readonly accept?: readonly Protocol[];
    readonly amount: Price;
    readonly description?: string;
    /** Merchant correlation id (order id, invoice number) echoed in receipts. */
    readonly externalId?: string;
    /** Fees added to the customer's total, keyed by recipient address. */
    readonly feeOnTop?: Readonly<Record<string, Price>>;
    /** Fees taken out of `amount`, keyed by recipient address. */
    readonly feeWithin?: Readonly<Record<string, Price>>;
    readonly name: string;
    /** Recipient of the base amount. Omit to inherit the operator recipient. */
    readonly payTo?: string;
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
    readonly name: string;
    readonly payTo: string;

    private constructor(params: {
        accept: readonly Protocol[];
        amount: Price;
        description: string | undefined;
        externalId: string | undefined;
        fees: readonly Fee[];
        name: string;
        payTo: string;
    }) {
        this.accept = Object.freeze([...params.accept]);
        this.amount = params.amount;
        this.description = params.description;
        this.externalId = params.externalId;
        this.fees = Object.freeze([...params.fees]);
        this.name = params.name;
        this.payTo = params.payTo;
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
        const fees: Fee[] = [
            ...Object.entries(params.feeWithin ?? {}).map(([recipient, price]) => ({
                kind: 'within' as const,
                price,
                recipient,
            })),
            ...Object.entries(params.feeOnTop ?? {}).map(([recipient, price]) => ({
                kind: 'on_top' as const,
                price,
                recipient,
            })),
        ];

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
        if (fees.length > 0) {
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
            name: params.name,
            payTo,
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
