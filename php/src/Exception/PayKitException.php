<?php

declare(strict_types=1);

namespace PayKit\Exception;

use Throwable;

/**
 * Catch-all marker every PayKit exception implements.
 *
 * Apps that want a generic "pay-kit failed" handler write
 * `catch (PayKitException $e)`; apps that want the typed leaves
 * catch the specific subclass (PaymentRequiredException,
 * InvalidProofException, ...). Both compose with the host
 * framework's exception pipeline through the same interface.
 */
interface PayKitException extends Throwable
{
}
