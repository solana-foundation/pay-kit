<?php

declare(strict_types=1);

namespace PayKit;

use PayKit\Exception\MixedCurrenciesException;
use PayKit\Exception\ProtocolIncompatibleException;
use InvalidArgumentException;
use PayKit\PayCore\Stablecoin;

/**
 * A protected unit. Carries the base amount, optional payTo override,
 * the ordered list of accepted Schemes, an optional description, and
 * zero or more named fees (within / on-top).
 *
 * All validation runs in the constructor; misconfigured gates die at
 * boot, not at request time. Six rules enforced:
 *
 *   1. Fixed amounts only (BigDecimal under the hood; no floats).
 *   2. One main recipient via `payTo` (defaults to operator.recipient).
 *   3. All fee prices share the gate amount's denom.
 *   4. sum(feeWithin values) <= amount.
 *   5. x402 auto-disabled when fees are present; explicit
 *      `accept: [Protocol::X402]` on a fee-bearing gate throws.
 *   6. Stablecoin preference is gate- or config-level, not per-fee.
 */
final readonly class Gate
{
    /** @var list<Fee> */
    public array $fees;

    /** @var list<Protocol>|null */
    public ?array $accept;

    /**
     * @param array<string,Price> $feeWithin Map of recipient => price; taken out of amount.
     * @param array<string,Price> $feeOnTop  Map of recipient => price; added on top.
     * @param list<Protocol>|null   $accept    Per-gate accept allowlist; null inherits from Config.
     */
    public function __construct(
        public Price $amount,
        public ?string $payTo = null,
        ?array $accept = null,
        public ?string $description = null,
        public ?string $externalId = null,
        array $feeWithin = [],
        array $feeOnTop = [],
    ) {
        $fees = [];
        foreach ($feeWithin as $recipient => $price) {
            $fees[] = self::buildFee($recipient, $price, Fee::KIND_WITHIN, $amount);
        }
        foreach ($feeOnTop as $recipient => $price) {
            $fees[] = self::buildFee($recipient, $price, Fee::KIND_ON_TOP, $amount);
        }

        // Rule 4: sum(feeWithin) <= amount
        $withinSum = $amount->amount->minus($amount->amount); // BigDecimal zero in same scale
        foreach ($fees as $f) {
            if ($f->isWithin()) {
                $withinSum = $withinSum->plus($f->price->amount);
            }
        }
        if ($withinSum->isGreaterThan($amount->amount)) {
            throw new InvalidArgumentException(
                'pay_kit: sum(feeWithin) exceeds amount on gate'
                . ($description !== null ? " (description={$description})" : ''),
            );
        }

        // Rule 5: x402 + fees is incompatible
        $hasFees = count($fees) > 0;
        if ($hasFees && $accept !== null && in_array(Protocol::X402, $accept, true)) {
            throw new ProtocolIncompatibleException(
                'pay_kit: explicit accept: [Protocol::X402] on a fee-bearing gate is invalid '
                . '(stock x402 facilitators settle to a single address)',
            );
        }
        // If no explicit accept, the resolver strips X402 silently when
        // fees are present. Mirror that here by leaving $accept null;
        // Adapter.detect() honors the fee-presence check.

        $this->fees   = $fees;
        $this->accept = $accept;
    }

    /**
     * Total amount the customer pays: base amount + sum(feeOnTop).
     */
    public function total(): Price
    {
        $total = $this->amount->amount;
        foreach ($this->fees as $f) {
            if ($f->isOnTop()) {
                $total = $total->plus($f->price->amount);
            }
        }
        return $this->amount->withAmount($total);
    }

    /**
     * What a given recipient nets, or null if not addressed by this gate.
     */
    public function payout(string $address): ?Price
    {
        // The primary recipient nets amount - sum(all feeWithin).
        if ($this->payTo === $address) {
            $net = $this->amount->amount;
            foreach ($this->fees as $f) {
                if ($f->isWithin()) {
                    $net = $net->minus($f->price->amount);
                }
            }
            return $this->amount->withAmount($net);
        }
        foreach ($this->fees as $f) {
            if ($f->recipient === $address) {
                return $f->price;
            }
        }
        return null;
    }

    public function hasFees(): bool
    {
        return count($this->fees) > 0;
    }

    private static function buildFee(int|string $recipient, Price $price, string $kind, Price $amount): Fee
    {
        if (!is_string($recipient) || $recipient === '') {
            throw new InvalidArgumentException('pay_kit: fee recipient must be a non-empty string');
        }
        if ($price->currency !== $amount->currency) {
            throw new MixedCurrenciesException(sprintf(
                'pay_kit: fee for %s is %s; gate amount is %s. All prices on a gate must share denom.',
                $recipient,
                $price->currency->value,
                $amount->currency->value,
            ));
        }
        return new Fee($recipient, $price, $kind);
    }
}
