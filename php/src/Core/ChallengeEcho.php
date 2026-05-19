<?php

declare(strict_types=1);

namespace SolanaMpp\Core;

final class ChallengeEcho
{
    public function __construct(
        public readonly string $id,
        public readonly string $realm,
        public readonly string $method,
        public readonly string $intent,
        public readonly string $request,
        public readonly string $expires = '',
        public readonly string $digest = '',
        public readonly ?string $opaque = null,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $value = [
            'id' => $this->id,
            'realm' => $this->realm,
            'method' => $this->method,
            'intent' => $this->intent,
            'request' => $this->request,
        ];
        if ($this->expires !== '') {
            $value['expires'] = $this->expires;
        }
        if ($this->digest !== '') {
            $value['digest'] = $this->digest;
        }
        if ($this->opaque !== null) {
            $value['opaque'] = $this->opaque;
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $value
     */
    public static function fromArray(array $value): self
    {
        return new self(
            id: (string)($value['id'] ?? ''),
            realm: (string)($value['realm'] ?? ''),
            method: (string)($value['method'] ?? ''),
            intent: (string)($value['intent'] ?? ''),
            request: (string)($value['request'] ?? ''),
            expires: (string)($value['expires'] ?? ''),
            digest: (string)($value['digest'] ?? ''),
            opaque: isset($value['opaque']) ? (string)$value['opaque'] : null,
        );
    }
}
