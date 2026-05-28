<?php

declare(strict_types=1);

namespace PayKit;

/**
 * Wire-level protocol that proves a payment.
 *
 * The backing string is what crosses the wire (lowercase, matches the
 * Rust spine and the cross-SDK matrix tables).
 */
enum Protocol: string
{
    case X402 = 'x402';
    case Mpp  = 'mpp';
}
