<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use PHPUnit\Framework\TestCase;
use SolanaMpp\Core\Receipt;

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
}
