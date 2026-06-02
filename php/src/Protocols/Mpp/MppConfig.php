<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp;

use PayKit\Exception\ConfigurationException;

/**
 * MPP scheme sub-configuration. `challengeBindingSecret` is the
 * spec's HMAC key for stateless challenge binding
 * (draft-httpauth-payment-00 sec. 5.1.2.1.1).
 *
 * Null `challengeBindingSecret` triggers Preflight's resolution chain
 * (env / .env / generate + persist) so the example apps boot without
 * the operator having to set anything.
 *
 * `expiresIn` is the challenge TTL in seconds. It is threaded into every
 * issued charge challenge as an RFC 3339 `expires` timestamp (see
 * {@see \PayKit\Protocols\Mpp\Adapter::challengeHeaders()}). The default
 * 120s matches the Python/Rust reference TTLs. Setting `expiresIn = 0` is
 * an explicit, documented development opt-out: challenges are issued with
 * no `expires`, so they never expire. Do not ship `0` to production.
 */
final readonly class MppConfig
{
    public function __construct(
        public string $realm = 'App',
        public ?string $challengeBindingSecret = null,
        public int $expiresIn = 120,
    ) {
        if ($expiresIn < 0) {
            throw new ConfigurationException(
                'pay_kit: mpp.expiresIn must be a non-negative number of seconds '
                . '(0 is the explicit dev-only never-expires opt-out)',
            );
        }
    }

    public function withChallengeBindingSecret(string $secret): self
    {
        return new self($this->realm, $secret, $this->expiresIn);
    }

    /**
     * Resolve a framework-config `expires_in` value into a safe TTL in
     * seconds without letting a malformed value silently collapse to the
     * never-expires opt-out.
     *
     * PHP's `(int)` cast turns `""`, `null`, or a non-numeric string (e.g. a
     * mis-typed `MPP_EXPIRES_IN` env) into `0`, which {@see MppConfig} accepts
     * as the explicit dev-only never-expires opt-out. Casting blindly would
     * therefore disable challenge expiry in production on a typo. This helper
     * distinguishes three cases:
     *
     *   - absent (`null`)           -> fall back to the safe 120s default;
     *   - explicit integer/numeric  -> use the parsed integer (incl. `0`);
     *   - present but non-numeric    -> fail fast with ConfigurationException.
     *
     * Only an explicit `0` (or `"0"`, `0.0`) yields the never-expires opt-out.
     *
     * @param mixed $value The raw configured value (typically from an array).
     * @param int   $default The TTL to use when the value is absent (`null`).
     */
    public static function resolveExpiresIn(mixed $value, int $default = 120): int
    {
        if ($value === null) {
            return $default;
        }

        if (is_int($value)) {
            return $value;
        }

        // Floats with an integer value (e.g. 0.0, 120.0) are accepted; a
        // fractional TTL is treated as malformed rather than truncated.
        if (is_float($value)) {
            if ($value === floor($value) && is_finite($value)) {
                return (int) $value;
            }
            throw new ConfigurationException(
                'pay_kit: mpp.expires_in must be a whole number of seconds, got a fractional value',
            );
        }

        // Booleans, arrays, objects, etc. are never a valid TTL. A bare `true`
        // would (int)-cast to 1 and a `false`/`[]` to 0; reject them outright.
        if (is_string($value)) {
            $trimmed = trim($value);
            if ($trimmed !== '' && (
                ctype_digit($trimmed)
                || (str_starts_with($trimmed, '-') && ctype_digit(substr($trimmed, 1)))
            )) {
                return (int) $trimmed;
            }
        }

        throw new ConfigurationException(
            'pay_kit: mpp.expires_in is set but is not a valid integer number of seconds '
            . '(empty/non-numeric values would silently disable challenge expiry; '
            . 'use an explicit 0 only for the documented dev-only never-expires opt-out)',
        );
    }
}
