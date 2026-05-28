<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\Mpp\Core;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PayKit\Protocols\Mpp\Core\Receipt;

final class ReceiptTest extends TestCase
{
    public function testOmitsEmptyOptionalFields(): void
    {
        $receipt = Receipt::success(method: 'solana', reference: 'sig');
        $value = $receipt->toArray();

        self::assertArrayNotHasKey('challengeId', $value);
        self::assertArrayNotHasKey('externalId', $value);
    }

    public function testIncludesOptionalFieldsWhenPresent(): void
    {
        $receipt = Receipt::success(
            method: 'solana',
            reference: 'sig',
            challengeId: 'challenge-id',
            externalId: 'order-1',
        );

        self::assertSame('challenge-id', $receipt->toArray()['challengeId']);
        self::assertSame('order-1', $receipt->toArray()['externalId']);
    }

    public function testSuccessTimestampIsNormalizedToUtc(): void
    {
        $receipt = Receipt::success(
            method: 'solana',
            reference: 'sig',
            now: new DateTimeImmutable('2026-05-19T03:30:00.123+03:00', new DateTimeZone('Europe/Istanbul')),
        );

        self::assertSame('2026-05-19T00:30:00.123Z', $receipt->timestamp);
    }

    public function testParsesReceiptFromArray(): void
    {
        $receipt = Receipt::fromArray([
            'status' => 'success',
            'method' => 'solana',
            'timestamp' => '2026-05-19T00:00:00.000Z',
            'reference' => 'sig',
            'challengeId' => 'challenge-id',
            'externalId' => 'order-1',
        ]);

        self::assertTrue($receipt->isSuccess());
        self::assertSame('challenge-id', $receipt->challengeId);
        self::assertSame('order-1', $receipt->externalId);
    }

    public function testRejectsMissingReceiptFields(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Receipt is missing required fields');

        Receipt::fromArray(['status' => 'success']);
    }
}
