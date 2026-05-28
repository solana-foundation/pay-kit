<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\Mpp\Core;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;

final class CredentialTest extends TestCase
{
    public function testAuthorizationHeaderRoundTrip(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1000', 'currency' => 'USDC']);
        $credential = new Credential(
            challenge: $challenge->toEcho(),
            payload: ['type' => 'signature', 'signature' => 'sig'],
            source: 'did:pkh:solana:test',
        );

        $parsed = Credential::fromAuthorizationHeader($credential->toAuthorizationHeader());

        self::assertSame($challenge->id, $parsed->challenge->id);
        self::assertEquals(['signature' => 'sig', 'type' => 'signature'], $parsed->payload);
        self::assertSame('did:pkh:solana:test', $parsed->source);
    }

    public function testExtractsPaymentSchemeFromMixedAuthorizationHeader(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $credential = new Credential(challenge: $challenge->toEcho(), payload: ['type' => 'signature']);

        $parsed = Credential::fromAuthorizationHeader('Bearer ignored, ' . $credential->toAuthorizationHeader());

        self::assertSame($challenge->id, $parsed->challenge->id);
    }

    public function testRejectsNonPaymentScheme(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Expected Payment scheme');

        Credential::fromAuthorizationHeader('Bearer token');
    }

    public function testRejectsOversizedCredentialToken(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Token exceeds maximum length of 16384 bytes');

        Credential::fromAuthorizationHeader('Payment ' . str_repeat('a', 16 * 1024 + 1));
    }

    public function testRejectsCredentialMissingChallengeObject(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid credential JSON structure');

        Credential::fromAuthorizationHeader('Payment ' . \PayKit\Protocols\Mpp\Core\Base64Url::encodeJson(['payload' => ['type' => 'signature']]));
    }

    public function testRejectsNonObjectPayload(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Credential payload must be an object');

        Credential::fromAuthorizationHeader('Payment ' . \PayKit\Protocols\Mpp\Core\Base64Url::encodeJson([
            'challenge' => $challenge->toEcho()->toArray(),
            'payload' => 'sig',
        ]));
    }
}
