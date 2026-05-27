<?php

declare(strict_types=1);

namespace PayKit;

use InvalidArgumentException;

/**
 * Optional base class for catalogue-style gate registries.
 *
 * Two equally-supported shapes:
 *
 *   1. Subclass Pricing, declare `public readonly Gate $foo` and
 *      assign in the constructor. Container-friendly, IDE-friendly.
 *   2. Build gates inline and pass them directly to RequirePayment
 *      without ever touching this class.
 *
 * The string-handle accessor (`$pricing->gate('report')`) is provided
 * for the Laravel middleware alias form (`middleware('paykit:report')`)
 * which is parameter-string-only by framework constraint.
 */
abstract class Pricing
{
    /**
     * Resolve a gate by name. Default implementation introspects
     * declared public properties via Reflection; override for a
     * registry-driven shape.
     */
    public function gate(string $name): Gate
    {
        if (!property_exists($this, $name)) {
            throw new InvalidArgumentException(
                sprintf('pay_kit: Pricing has no gate "%s"', $name),
            );
        }
        $value = $this->{$name};
        if (!$value instanceof Gate) {
            throw new InvalidArgumentException(
                sprintf('pay_kit: Pricing::$%s is not a Gate', $name),
            );
        }
        return $value;
    }
}
