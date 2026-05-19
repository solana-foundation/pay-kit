<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Challenge;

final class ChallengeTest extends TestCase
{
    public function testCreatesHmacBoundChallenge(): void
    {
        $challenge = Challenge::withSecret(
            secretKey: 'secret',
            realm: 'api',
            method: 'solana',
            intent: 'charge',
            request: ['amount' => '1000', 'currency' => 'USDC'],
            expires: '2099-01-01T00:00:00+00:00',
        );

        self::assertTrue($challenge->verify('secret'));
        self::assertFalse($challenge->verify('wrong-secret'));
        self::assertSame(['amount' => '1000', 'currency' => 'USDC'], $challenge->decodeRequest());
        self::assertFalse($challenge->isExpired(new DateTimeImmutable('2026-01-01T00:00:00+00:00')));
    }

    public function testChallengeEchoPreservesWireFields(): void
    {
        $challenge = Challenge::withSecret('secret', 'api', 'solana', 'charge', ['amount' => '1', 'currency' => 'USDC']);
        $echo = $challenge->toEcho()->toArray();

        self::assertSame($challenge->id, $echo['id']);
        self::assertSame('solana', $echo['method']);
        self::assertSame('charge', $echo['intent']);
        self::assertSame($challenge->request, $echo['request']);
    }
}
