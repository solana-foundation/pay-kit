<?php

declare(strict_types=1);

// Aggregate leaf exception classes. Each is small (a few lines)
// because they exist only to give callers a typed `catch` target;
// the actual behavior lives in the framework adapter that converts
// the exception to an HTTP response. Keeping them in one file
// instead of one-class-per-file (per Ludo PR #145 review) keeps the
// src/Exception/ directory readable without losing PSR-4 friendliness
// for the shared interface in PayKitException.php.

namespace PayKit\Exception;

use InvalidArgumentException;
use LogicException;
use RuntimeException;

/**
 * Boot-time misconfiguration the operator must resolve before the
 * app can serve traffic. Examples: invalid network slug, preflight
 * check found the fee-payer has zero SOL on the configured RPC, the
 * recipient has no ATA for one of the accepted stablecoins.
 */
final class ConfigurationException extends RuntimeException implements PayKitException
{
}

/**
 * Boot-time guard: the package-shipped demo keypair will never be
 * used as the operator on Solana mainnet. Production deployments
 * must load a real keypair via Signer::file / Signer::env.
 */
final class DemoSignerOnMainnetException extends LogicException implements PayKitException
{
}

/**
 * Thrown by Signer factories when a secret cannot be parsed
 * (malformed JSON array, wrong byte length, invalid base58, ...).
 * Boot-time only; never reaches a request handler.
 */
final class InvalidKeyException extends InvalidArgumentException implements PayKitException
{
}

/**
 * Boot-time failure: a Gate mixes prices in different denominations
 * (e.g. one USD fee and one EUR fee on the same gate).
 */
final class MixedCurrenciesException extends InvalidArgumentException implements PayKitException
{
}

/**
 * Boot-time failure: a Gate explicitly accepts a scheme that cannot
 * settle the gate's shape (e.g. x402 on a fee-bearing gate).
 */
final class ProtocolIncompatibleException extends InvalidArgumentException implements PayKitException
{
}

/**
 * Thrown when a submitted payment proof is structurally invalid: a
 * malformed Authorization header, a transaction whose shape does not
 * match the offer, a signature that does not verify, etc. The
 * framework adapter typically renders this as HTTP 402 with a fresh
 * challenge.
 */
class InvalidProofException extends RuntimeException implements PayKitException
{
    public function httpStatus(): int
    {
        return 402;
    }
}

/**
 * Thrown when a credential's challenge has aged past
 * `MppConfig::$expiresIn`. Subclass of InvalidProofException so the
 * generic "bad proof, re-issue challenge" handler still catches it.
 */
final class ChallengeExpiredException extends InvalidProofException
{
}

/**
 * Thrown when a request reaches a gated route without a valid
 * payment. Framework adapters convert this to an HTTP 402.
 */
final class PaymentRequiredException extends RuntimeException implements PayKitException
{
    public function httpStatus(): int
    {
        return 402;
    }
}

/**
 * Thrown when a client requests a scheme the server's config does
 * not accept (e.g. x402 against an MPP-only deployment).
 */
final class ProtocolNotSupportedException extends RuntimeException implements PayKitException
{
    public function httpStatus(): int
    {
        return 406;
    }
}
