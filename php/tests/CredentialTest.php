<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;

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
        self::assertSame(['type' => 'signature', 'signature' => 'sig'], $parsed->payload);
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
}
