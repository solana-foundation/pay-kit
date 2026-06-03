<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402\Exact;

/**
 * Typed view over the x402 v2 `extensions` object that rides on BOTH the
 * inbound `PAYMENT-REQUIRED` challenge and the outbound `PAYMENT-SIGNATURE`
 * credential. Mirrors the rust spine `PaymentExtensions` (commit 90235392,
 * crates/x402/src/protocol/schemes/exact/types.rs:513-565).
 *
 * Known extensions are fielded out (`payment-identifier`); unknown ones flow
 * through `$other` verbatim so the echo-and-append rule (x402 v2 §5.1.2) does
 * not drop forward-compatible payloads. The spec JSON key for the
 * payment-identifier extension is kebab-case `payment-identifier` (rust
 * `#[serde(rename = "payment-identifier")]`); `info` is camelCase
 * `{ required?, id? }`, and `schema?` is echoed verbatim.
 */
final class PaymentExtensions
{
    /** Wire key for the payment-identifier extension (kebab-case, rust rename). */
    public const PAYMENT_IDENTIFIER_KEY = 'payment-identifier';

    /**
     * @param ?PaymentIdentifierExtension $paymentIdentifier The
     *        `payment-identifier` idempotency extension. Some providers mark
     *        `info.required = true` and reject requests that do not echo a
     *        `pay_…` id back.
     * @param array<string,mixed> $other Forward-compatible storage for
     *        extensions this SDK does not type natively. Captured during echo,
     *        re-emitted verbatim (rust `#[serde(flatten)] other`).
     */
    public function __construct(
        public readonly ?PaymentIdentifierExtension $paymentIdentifier = null,
        public readonly array $other = [],
    ) {
    }

    /**
     * Echo a server's inbound extensions blob (the `extensions` object carried
     * on the `PAYMENT-REQUIRED` challenge) into a typed instance. Returns null
     * when the inbound is absent so the outbound omits the object entirely
     * (rust `PaymentExtensions::echoing` -> `Ok(None)`; types.rs:559-565).
     *
     * @param array<string,mixed>|null $inbound
     */
    public static function echoing(?array $inbound): ?self
    {
        if ($inbound === null) {
            return null;
        }

        $paymentIdentifier = null;
        $other = [];
        foreach ($inbound as $key => $value) {
            if ($key === self::PAYMENT_IDENTIFIER_KEY) {
                $paymentIdentifier = is_array($value)
                    ? PaymentIdentifierExtension::fromArray($value)
                    : null;
                continue;
            }
            // Preserve unknown extensions verbatim (rust `other` flatten map).
            $other[$key] = $value;
        }

        return new self($paymentIdentifier, $other);
    }

    /**
     * Construct from the typed decode of an outbound credential's `extensions`
     * object (same wire shape as {@see echoing}). Used by the server verify
     * path to read back what a client echoed.
     *
     * @param array<string,mixed>|null $value
     */
    public static function fromArray(?array $value): ?self
    {
        return self::echoing($value);
    }

    /**
     * True when no fields are populated, so callers avoid emitting an empty
     * `extensions: {}` on outbound envelopes (rust `is_empty`; types.rs:533-535).
     */
    public function isEmpty(): bool
    {
        return $this->paymentIdentifier === null && $this->other === [];
    }

    /**
     * `payment-identifier.info.required === true` (rust
     * `requires_payment_identifier`; types.rs:538-543).
     */
    public function requiresPaymentIdentifier(): bool
    {
        return $this->paymentIdentifier?->info->required === true;
    }

    /**
     * Set (or overwrite) the client-side `payment-identifier.info.id`, creating
     * the extension entry if the server did not advertise one. Preserves the
     * server-side `info.required` and `schema` verbatim, never overwriting them
     * (rust `with_payment_identifier_id`; types.rs:548-553).
     */
    public function withPaymentIdentifierId(string $id): self
    {
        $existing = $this->paymentIdentifier ?? new PaymentIdentifierExtension();
        $entry = new PaymentIdentifierExtension(
            info: new PaymentIdentifierInfo(
                required: $existing->info->required,
                id: $id,
            ),
            schema: $existing->schema,
        );

        return new self($entry, $this->other);
    }

    /**
     * Serialize to the wire object, with the kebab-case payment-identifier key
     * first and unknown extensions flattened verbatim. The payment-identifier
     * entry is omitted when null; absent optionals inside it are likewise
     * omitted (mirrors rust `skip_serializing_if = "Option::is_none"`).
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        $out = [];
        if ($this->paymentIdentifier !== null) {
            $out[self::PAYMENT_IDENTIFIER_KEY] = $this->paymentIdentifier->toArray();
        }
        foreach ($this->other as $key => $value) {
            $out[$key] = $value;
        }

        return $out;
    }

    /**
     * Generate a fresh `pay_`-prefixed idempotency id (32 lowercase hex chars
     * after the prefix; 36 total). Satisfies the payment-identifier spec
     * pattern `^[A-Za-z0-9_-]{16,128}$` and the canonical Solana
     * `^pay_[a-zA-Z0-9_-]{10,120}$` shape. Callers MUST reuse the same id
     * across retries of the same logical request so the server can return a
     * cached 200 instead of charging twice (rust
     * `generate_payment_identifier_id`; types.rs:575-585).
     */
    public static function generatePaymentIdentifierId(): string
    {
        return 'pay_' . bin2hex(random_bytes(16));
    }
}
