<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use DateTimeImmutable;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Headers;
use SolanaMpp\Core\Receipt;

final class HeadersTest extends TestCase
{
    public function testWwwAuthenticateRoundTrip(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1000', 'currency' => 'USDC'],
            expires: '2099-01-01T00:00:00+00:00',
            digest: 'sha-256=abc',
            opaque: 'opaque',
        );

        $parsed = Headers::parseWwwAuthenticate(Headers::formatWwwAuthenticate($challenge));

        self::assertSame($challenge->id, $parsed->id);
        self::assertSame($challenge->realm, $parsed->realm);
        self::assertSame($challenge->request, $parsed->request);
        self::assertSame($challenge->digest, $parsed->digest);
        self::assertTrue($parsed->verify('secret'));
    }

    public function testParsesPaymentChallengeFromMixedHeader(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $header = 'Bearer realm="ignored", ' . Headers::formatWwwAuthenticate($challenge);

        self::assertSame($challenge->id, Headers::parseWwwAuthenticate($header)->id);
    }

    public function testRejectsInvalidChallengeHeader(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Expected Payment scheme');

        Headers::parseWwwAuthenticate('Bearer realm="api"');
    }

    public function testRejectsDuplicateAuthParams(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $header = Headers::formatWwwAuthenticate($challenge) . ', method="solana"';

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Duplicate auth parameter');

        Headers::parseWwwAuthenticate($header);
    }

    public function testRejectsCrlfInFormattedAuthParams(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: "api\r\nx-injected: 1",
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1', 'currency' => 'USDC'],
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid header value');

        Headers::formatWwwAuthenticate($challenge);
    }

    public function testReceiptHeaderRoundTrip(): void
    {
        $receipt = Receipt::success(
            method: 'solana',
            reference: 'reference',
            challengeId: 'challenge-id',
            externalId: 'order-001',
            now: new DateTimeImmutable('2026-05-19T00:00:00+00:00'),
        );

        $parsed = Headers::parseReceipt(Headers::formatReceipt($receipt));

        self::assertTrue($parsed->isSuccess());
        self::assertSame('solana', $parsed->method);
        self::assertSame('reference', $parsed->reference);
        self::assertSame('challenge-id', $parsed->challengeId);
        self::assertSame('order-001', $parsed->externalId);
    }
}
