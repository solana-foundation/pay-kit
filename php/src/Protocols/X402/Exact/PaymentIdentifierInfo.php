<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402\Exact;

/**
 * Client/server-side fields of the `payment-identifier` extension. Mirrors the
 * rust spine `PaymentIdentifierInfo` (commit 90235392, types.rs:481-494). Wire
 * keys are camelCase; both fields are optional and omitted when null.
 *
 * @see https://github.com/coinbase/x402/blob/main/specs/extensions/payment_identifier.md
 */
final class PaymentIdentifierInfo
{
    /** `id` must match this pattern (rust types.rs:488). */
    public const ID_PATTERN = '/^[A-Za-z0-9_-]{16,128}$/';

    /**
     * @param ?bool $required Server-side: whether clients MUST populate `id`.
     *        When true and `id` is missing, the server returns HTTP 400.
     * @param ?string $id Client-side idempotency key. Must match
     *        {@see ID_PATTERN}; canonical Solana implementations use a `pay_`
     *        prefix (e.g. `pay_7d5d747be160e280504c099d984bcfe0`).
     */
    public function __construct(
        public readonly ?bool $required = null,
        public readonly ?string $id = null,
    ) {
    }

    /**
     * @param array<string,mixed> $value
     */
    public static function fromArray(array $value): self
    {
        return new self(
            required: array_key_exists('required', $value) && is_bool($value['required'])
                ? $value['required']
                : null,
            id: array_key_exists('id', $value) && is_string($value['id'])
                ? $value['id']
                : null,
        );
    }

    /** True when `id` is present and matches the spec pattern. */
    public function hasValidId(): bool
    {
        return is_string($this->id)
            && $this->id !== ''
            && preg_match(self::ID_PATTERN, $this->id) === 1;
    }

    /**
     * Wire object with absent optionals omitted (rust
     * `skip_serializing_if = "Option::is_none"`).
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        $out = [];
        if ($this->required !== null) {
            $out['required'] = $this->required;
        }
        if ($this->id !== null) {
            $out['id'] = $this->id;
        }

        return $out;
    }
}
