<?php

declare(strict_types=1);

namespace PayKit;

/**
 * One recipient line on a Gate. Either taken `within` the amount (the
 * payTo recipient nets less) or `onTop` (customer pays more, payTo
 * nets full).
 *
 * Frozen at construction. Built by Gate from the `feeWithin` /
 * `feeOnTop` constructor args.
 */
final readonly class Fee
{
    public const KIND_WITHIN = 'within';
    public const KIND_ON_TOP = 'on_top';

    public function __construct(
        public string $recipient,
        public Price $price,
        public string $kind,
    ) {
    }

    public function isWithin(): bool
    {
        return $this->kind === self::KIND_WITHIN;
    }

    public function isOnTop(): bool
    {
        return $this->kind === self::KIND_ON_TOP;
    }
}
