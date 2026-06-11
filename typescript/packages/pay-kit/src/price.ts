import { ConfigurationError, MixedCurrenciesError } from './errors.js';

/** Fiat currencies a {@link Price} can be denominated in. */
export type Currency = 'EUR' | 'GBP' | 'USD';

/** Stablecoins a {@link Price} can settle in. */
export type Stablecoin = 'CASH' | 'PYUSD' | 'USDC' | 'USDG' | 'USDT';

/** All supported settlement stablecoins, in no particular order. */
export const STABLECOINS: readonly Stablecoin[] = ['CASH', 'PYUSD', 'USDC', 'USDG', 'USDT'];

const AMOUNT_PATTERN = /^[0-9]+(?:\.[0-9]{1,6})?$/;
const MICRO = 1_000_000n;

function toMicro(amount: string): bigint {
    if (!AMOUNT_PATTERN.test(amount)) {
        throw new ConfigurationError(
            `Invalid amount "${amount}". Use a non-negative decimal string with at most 6 decimal places.`,
        );
    }
    const [whole = '0', frac = ''] = amount.split('.');
    return BigInt(whole) * MICRO + BigInt(`${frac}000000`.slice(0, 6));
}

function fromMicro(micro: bigint): string {
    const whole = micro / MICRO;
    const frac = (micro % MICRO).toString().padStart(6, '0').replace(/0+$/, '');
    return frac === '' ? `${whole}` : `${whole}.${frac}`;
}

/**
 * A denominated amount: fiat currency, decimal amount, and an ordered list of
 * stablecoins the amount may settle in. Immutable; arithmetic is exact
 * (fixed-point, no floats).
 *
 * @example
 * ```ts
 * import { usd } from '@solana/pay-kit';
 *
 * const price = usd('0.10');
 * price.baseUnits();      // 100000n (6 decimals)
 * price.plus(usd('0.05')) // USD 0.15
 * ```
 */
export class Price {
    /** Canonical decimal string, e.g. `"0.10"`. */
    readonly amount: string;
    readonly currency: Currency;
    /** Ordered settlement preference. Empty means "inherit from config". */
    readonly settlements: readonly Stablecoin[];

    private constructor(currency: Currency, amount: string, settlements: readonly Stablecoin[]) {
        this.amount = fromMicro(toMicro(amount));
        this.currency = currency;
        this.settlements = Object.freeze([...settlements]);
        Object.freeze(this);
    }

    /** Creates a EUR price. */
    static eur(amount: string, ...settlements: Stablecoin[]): Price {
        return new Price('EUR', amount, settlements);
    }

    /** Creates a GBP price. */
    static gbp(amount: string, ...settlements: Stablecoin[]): Price {
        return new Price('GBP', amount, settlements);
    }

    /** Creates a USD price. */
    static usd(amount: string, ...settlements: Stablecoin[]): Price {
        return new Price('USD', amount, settlements);
    }

    /** Wire-form decimal string (alias for {@link Price.amount}). */
    amountString(): string {
        return this.amount;
    }

    /**
     * The amount in on-chain base units.
     *
     * @param decimals - Token decimals of the settlement asset (6 for all supported stablecoins).
     */
    baseUnits(decimals = 6): bigint {
        const micro = toMicro(this.amount);
        if (decimals === 6) return micro;
        return decimals > 6 ? micro * 10n ** BigInt(decimals - 6) : micro / 10n ** BigInt(6 - decimals);
    }

    /** Compares two same-currency prices. @throws {MixedCurrenciesError} on currency mismatch. */
    isGreaterThan(other: Price): boolean {
        this.#assertSameCurrency(other);
        return toMicro(this.amount) > toMicro(other.amount);
    }

    /** Sums two same-currency prices. @throws {MixedCurrenciesError} on currency mismatch. */
    plus(other: Price): Price {
        this.#assertSameCurrency(other);
        return new Price(this.currency, fromMicro(toMicro(this.amount) + toMicro(other.amount)), this.settlements);
    }

    /** First settlement preference, if one was set explicitly. */
    primaryCoin(): Stablecoin | undefined {
        return this.settlements[0];
    }

    /**
     * Subtracts a same-currency price.
     *
     * @throws {MixedCurrenciesError} on currency mismatch or negative result.
     */
    minus(other: Price): Price {
        this.#assertSameCurrency(other);
        const result = toMicro(this.amount) - toMicro(other.amount);
        if (result < 0n) {
            throw new ConfigurationError(`Cannot subtract ${other.amount} from ${this.amount}: negative result.`);
        }
        return new Price(this.currency, fromMicro(result), this.settlements);
    }

    /** Copy with a different amount, same currency and settlements. */
    withAmount(amount: string): Price {
        return new Price(this.currency, amount, this.settlements);
    }

    #assertSameCurrency(other: Price): void {
        if (other.currency !== this.currency) {
            throw new MixedCurrenciesError(`Cannot combine ${this.currency} with ${other.currency}.`);
        }
    }
}

/** Shorthand for {@link Price.usd}. */
export function usd(amount: string, ...settlements: Stablecoin[]): Price {
    return Price.usd(amount, ...settlements);
}

/** Shorthand for {@link Price.eur}. */
export function eur(amount: string, ...settlements: Stablecoin[]): Price {
    return Price.eur(amount, ...settlements);
}

/** Shorthand for {@link Price.gbp}. */
export function gbp(amount: string, ...settlements: Stablecoin[]): Price {
    return Price.gbp(amount, ...settlements);
}
