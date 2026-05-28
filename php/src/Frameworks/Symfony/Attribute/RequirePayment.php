<?php

declare(strict_types=1);

namespace PayKit\Frameworks\Symfony\Attribute;

use Attribute;

/**
 * Symfony controller-action attribute. Mirrors Laravel's
 * `middleware('paykit:report')` and Ruby's `require_payment! :report`.
 * Pair with {@see \PayKit\Frameworks\Symfony\EventListener\RequirePaymentListener}
 * which intercepts kernel.controller_arguments and gates the action.
 *
 * Usage:
 *
 *   #[Route('/report')]
 *   #[RequirePayment('report')]
 *   public function show(Request $r): JsonResponse { ... }
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class RequirePayment
{
    public function __construct(public readonly string $gate)
    {
    }
}
