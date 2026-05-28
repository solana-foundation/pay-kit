<?php

declare(strict_types=1);

namespace PayKit;

use Brick\Math\BigDecimal;
use Brick\Math\Exception\NumberFormatException;
use InvalidArgumentException;
use PayKit\PayCore\Currency;
use PayKit\PayCore\Stablecoin;

/**
 * Denominated amount + ordered settlement preference list.
 *
 * `Price::usd('0.10')` reads "ten cents USD, settle in whatever the
 * config prefers". `Price::usd('0.10', Stablecoin::Usdc)` narrows the
 * settlement to USDC only. Order of the variadic stablecoin args is
 * preference; the resolver picks the first one it can settle.
 *
 * Amounts are stored as Brick\Math\BigDecimal. The constructor rejects
 * floats at the signature level (string | int | BigDecimal); use the
 * named-constructor static methods instead of `new Price(...)`.
 */
final readonly class Price
{
    /** @var list<Stablecoin> */
    public array $settlements;

    private function __construct(
        public BigDecimal $amount,
        public Currency $currency,
        Stablecoin ...$settlements,
    ) {
        $this->settlements = $settlements;
    }

    /**
     * Build a USD-denominated price.
     *
     * @param string|int|BigDecimal $amount Decimal-safe amount (e.g. "0.10").
     */
    public static function usd(string|int|BigDecimal $amount, Stablecoin ...$settlements): self
    {
        return new self(self::toBigDecimal($amount), Currency::Usd, ...$settlements);
    }

    public static function eur(string|int|BigDecimal $amount, Stablecoin ...$settlements): self
    {
        return new self(self::toBigDecimal($amount), Currency::Eur, ...$settlements);
    }

    public static function gbp(string|int|BigDecimal $amount, Stablecoin ...$settlements): self
    {
        return new self(self::toBigDecimal($amount), Currency::Gbp, ...$settlements);
    }

    /**
     * Return a copy with a new amount, same denom + settlements.
     */
    public function withAmount(string|int|BigDecimal $amount): self
    {
        return new self(self::toBigDecimal($amount), $this->currency, ...$this->settlements);
    }

    /**
     * Sum two same-denom prices. Throws on denom mismatch.
     */
    public function plus(self $other): self
    {
        if ($this->currency !== $other->currency) {
            throw new InvalidArgumentException(
                sprintf(
                    'pay_kit: cannot sum prices of different currencies (%s vs %s)',
                    $this->currency->value,
                    $other->currency->value
                ),
            );
        }
        return new self(
            $this->amount->plus($other->amount),
            $this->currency,
            ...$this->settlements,
        );
    }

    /**
     * The wire-form decimal string (preserves trailing zeros).
     */
    public function amountString(): string
    {
        return (string) $this->amount;
    }

    /**
     * The most-preferred settlement coin, or null when the price was
     * built without an explicit list (resolver falls back to the
     * config-level stablecoins).
     */
    public function primaryCoin(): ?Stablecoin
    {
        return $this->settlements[0] ?? null;
    }

    private static function toBigDecimal(string|int|BigDecimal $amount): BigDecimal
    {
        if ($amount instanceof BigDecimal) {
            return $amount;
        }
        try {
            return BigDecimal::of($amount);
        } catch (NumberFormatException $e) {
            throw new InvalidArgumentException(
                'pay_kit: invalid Price amount: ' . $e->getMessage(),
                previous: $e,
            );
        }
    }
}
