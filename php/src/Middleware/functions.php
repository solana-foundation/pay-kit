<?php

declare(strict_types=1);

namespace PayKit\Middleware;

use PayKit\Exception\PaymentRequiredException;
use PayKit\Gate;
use PayKit\Payment;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Request-scoped trio. Mirrors Ruby's `payment` / `paid?` /
 * `require_payment!` and the cross-SDK shape.
 *
 * The RequirePayment middleware attaches the verified Payment to the
 * request as the `paykit.payment` attribute; these helpers read it
 * back. Import per file:
 *
 *   use function PayKit\Http\{payment, isPaid, isPaidFor, requirePayment};
 */

/**
 * The verified payment proof, or null if no PayKit middleware ran
 * against this request.
 */
function payment(ServerRequestInterface $request): ?Payment
{
    $value = $request->getAttribute('paykit.payment');
    return $value instanceof Payment ? $value : null;
}

function isPaid(ServerRequestInterface $request): bool
{
    return payment($request) !== null;
}

function isPaidFor(ServerRequestInterface $request, Gate|string $gate): bool
{
    $pmt = payment($request);
    if ($pmt === null) {
        return false;
    }
    if ($gate instanceof Gate) {
        // Gate identity is not carried on Payment by default; assume
        // the middleware that wrote the attribute matched the gate.
        return true;
    }
    return $pmt->gateName === $gate;
}

/**
 * Imperative-style gating from inside a handler. Throws
 * {@see PaymentRequiredException} when no payment is attached.
 */
function requirePayment(ServerRequestInterface $request): Payment
{
    $pmt = payment($request);
    if ($pmt === null) {
        throw new PaymentRequiredException('pay_kit: payment required');
    }
    return $pmt;
}
