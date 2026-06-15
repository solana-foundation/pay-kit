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
 *
 * `realm` is part of the HMAC id input, so two services sharing one
 * `challengeBindingSecret` and keeping the same realm would share a single
 * credential namespace — a credential paid against service A would pass HMAC
 * verification on service B (audit #15). The default is therefore `null`,
 * which {@see resolveRealm()} turns into a value derived from the server's
 * recipient pubkey (unique per merchant). An explicit empty-string realm is
 * rejected so an operator cannot re-introduce the shared namespace by typo.
 */
final readonly class MppConfig
{
    public function __construct(
        public ?string $realm = null,
        public ?string $challengeBindingSecret = null,
        public int $expiresIn = 120,
        public bool $acceptPushMode = false,
    ) {
        if ($expiresIn < 0) {
            throw new ConfigurationException(
                'pay_kit: mpp.expiresIn must be a non-negative number of seconds '
                . '(0 is the explicit dev-only never-expires opt-out)',
            );
        }
        if ($realm !== null && trim($realm) === '') {
            throw new ConfigurationException(
                'pay_kit: mpp.realm must be a non-empty string or null (null derives a '
                . 'per-recipient default; an empty realm would share a credential namespace '
                . 'across servers — audit #15)',
            );
        }
    }

    public function withChallengeBindingSecret(string $secret): self
    {
        return new self($this->realm, $secret, $this->expiresIn, $this->acceptPushMode);
    }

    /**
     * Resolve the effective realm for a server serving `$recipient`.
     *
     * Returns the explicitly-configured realm when one is set, otherwise
     * derives a deterministic per-recipient default of the shape
     * `"App Id - #<digits>"` (mirrors Rust `derive_default_realm`,
     * rust/crates/mpp/src/server/charge.rs). Deriving from the recipient
     * pubkey — unique per merchant and already mandatory upstream — means two
     * services sharing a secret but paying different recipients get distinct
     * realms, distinct HMAC ids, and cannot replay credentials across each
     * other (audit #15).
     */
    public function resolveRealm(string $recipient): string
    {
        if ($this->realm !== null) {
            return $this->realm;
        }
        if ($recipient === '') {
            throw new ConfigurationException(
                'pay_kit: cannot derive a default mpp.realm without a recipient; '
                . 'set mpp.realm explicitly or configure a recipient',
            );
        }

        $digest = hash('sha256', $recipient, true);
        $first4 = substr($digest, 0, 4);
        $unpacked = unpack('Nvalue', $first4);
        $value = is_array($unpacked) && is_int($unpacked['value']) ? $unpacked['value'] : 0;

        return sprintf('App Id - #%d', $value % 100_000_000);
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
