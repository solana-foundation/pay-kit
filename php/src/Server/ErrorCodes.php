<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

/**
 * Canonical L6 / P1 structured error codes for 402 Payment Required bodies.
 *
 * Mirrors the cross-SDK lock from PR #96 / #102 / #106: every server SDK
 * returns the same canonical `code` field for the same failure class so a
 * polyglot client can route on the code alone, independent of the human
 * `detail` message.
 *
 * - `CHARGE_REQUEST_MISMATCH`: the credential's claimed charge does not
 *   match the route's expected charge (amount, currency, recipient).
 * - `CHALLENGE_ROUTE_MISMATCH`: the credential was issued for a different
 *   route (different method, intent, or realm) than the one being requested.
 * - `CHALLENGE_VERIFICATION_FAILED`: HMAC verification of the challenge id
 *   failed or the credential could not be parsed.
 * - `CHALLENGE_EXPIRED`: the challenge's `expires` is in the past.
 * - `PAYMENT_INVALID`: the credential payload is malformed or fails on-chain
 *   verification (decode error, instruction allowlist violation, amount or
 *   recipient mismatch on the wire transaction).
 * - `WRONG_NETWORK`: the credential was signed against a different network
 *   than the one the server is configured for (e.g. Surfpool blockhash on
 *   mainnet).
 * - `SIGNATURE_CONSUMED`: the on-chain signature has already been used to
 *   settle a previous charge.
 */
final class ErrorCodes
{
    public const CHARGE_REQUEST_MISMATCH = 'charge_request_mismatch';
    public const CHALLENGE_ROUTE_MISMATCH = 'challenge_route_mismatch';
    public const CHALLENGE_VERIFICATION_FAILED = 'challenge_verification_failed';
    public const CHALLENGE_EXPIRED = 'challenge_expired';
    public const PAYMENT_INVALID = 'payment_invalid';
    public const WRONG_NETWORK = 'wrong_network';
    public const SIGNATURE_CONSUMED = 'signature_consumed';

    /** @return list<string> */
    public static function all(): array
    {
        return [
            self::CHARGE_REQUEST_MISMATCH,
            self::CHALLENGE_ROUTE_MISMATCH,
            self::CHALLENGE_VERIFICATION_FAILED,
            self::CHALLENGE_EXPIRED,
            self::PAYMENT_INVALID,
            self::WRONG_NETWORK,
            self::SIGNATURE_CONSUMED,
        ];
    }

    /**
     * Map a verification reason string (the human `detail` message) to the
     * best canonical error code. Falls back to `PAYMENT_INVALID` so a 402
     * response always carries a canonical L6 code.
     *
     * Verifier rejections raise `InvalidArgumentException` with a free-form
     * message that bubbles up to the response builder; this mapping lets
     * call sites avoid threading an explicit code through every throw site
     * while still emitting a canonical code in the body.
     */
    public static function fromReason(string $reason): string
    {
        return match (true) {
            $reason === 'charge request mismatch' => self::CHARGE_REQUEST_MISMATCH,
            $reason === 'challenge verification failed' => self::CHALLENGE_VERIFICATION_FAILED,
            $reason === 'invalid payment credential' => self::CHALLENGE_VERIFICATION_FAILED,
            $reason === 'challenge expired' => self::CHALLENGE_EXPIRED,
            $reason === 'challenge method or intent mismatch' => self::CHALLENGE_ROUTE_MISMATCH,
            $reason === 'challenge realm mismatch' => self::CHALLENGE_ROUTE_MISMATCH,
            $reason === 'Transaction signature already consumed' => self::SIGNATURE_CONSUMED,
            str_contains($reason, 'Surfpool localnet blockhash') => self::WRONG_NETWORK,
            default => self::PAYMENT_INVALID,
        };
    }

    /**
     * Map a reason raised during credential-and-challenge verification (the
     * path that runs before the structural transaction verifier) to a
     * canonical code.
     *
     * `ChargeServer::verifyAuthorizationHeader()` catches every parse-time
     * `InvalidArgumentException` from `Credential::fromAuthorizationHeader()`
     * and the challenge echo parser, and passes the raw message through. The
     * full set of messages is large (`Invalid JSON value`, `Token exceeds
     * maximum length`, `id must be a string`, etc.) but every failure on
     * this path describes either a malformed credential, a malformed
     * challenge, or a route mismatch. The mapping below classifies the
     * specific ones we care about and defaults to
     * `CHALLENGE_VERIFICATION_FAILED` instead of falling through to
     * `PAYMENT_INVALID`, because a payload-level failure cannot reach this
     * branch without first passing credential and challenge parsing.
     */
    public static function fromAuthVerificationReason(string $reason): string
    {
        return match (true) {
            $reason === 'charge request mismatch' => self::CHARGE_REQUEST_MISMATCH,
            $reason === 'challenge expired' => self::CHALLENGE_EXPIRED,
            $reason === 'challenge method or intent mismatch' => self::CHALLENGE_ROUTE_MISMATCH,
            $reason === 'challenge realm mismatch' => self::CHALLENGE_ROUTE_MISMATCH,
            default => self::CHALLENGE_VERIFICATION_FAILED,
        };
    }
}
