<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402\Exact;

/**
 * The `payment-identifier` extension. Echoed by the client into the outbound
 * `PAYMENT-SIGNATURE` with `info.id` populated. Mirrors the rust spine
 * `PaymentIdentifierExtension` (commit 90235392, types.rs:498-507).
 */
final class PaymentIdentifierExtension
{
    /**
     * @param PaymentIdentifierInfo $info Required client-side / server-side
     *        info block (rust `#[serde(default)] info`).
     * @param mixed $schema JSON Schema published by the server describing the
     *        required client-side fields. Echoed verbatim per x402 v2 §5.1.2;
     *        null when the server published none.
     */
    public function __construct(
        public readonly PaymentIdentifierInfo $info = new PaymentIdentifierInfo(),
        public readonly mixed $schema = null,
    ) {
    }

    /**
     * @param array<string,mixed> $value
     */
    public static function fromArray(array $value): self
    {
        $info = is_array($value['info'] ?? null)
            ? PaymentIdentifierInfo::fromArray($value['info'])
            : new PaymentIdentifierInfo();

        return new self(
            info: $info,
            schema: array_key_exists('schema', $value) ? $value['schema'] : null,
        );
    }

    /**
     * Wire object: `info` always present (matching rust default), `schema`
     * echoed verbatim only when the server published one.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        $out = ['info' => $this->info->toArray()];
        if ($this->schema !== null) {
            $out['schema'] = $this->schema;
        }

        return $out;
    }
}
