<?php

declare(strict_types=1);

namespace SolanaMpp\Tests;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use SolanaMpp\Intent\ChargeRequest;

final class ChargeRequestTest extends TestCase
{
    public function testRoundTripsChargeRequest(): void
    {
        $request = new ChargeRequest(
            amount: '1000',
            currency: 'USDC',
            recipient: 'recipient',
            description: 'Protected content',
            externalId: 'order-001',
            methodDetails: ['network' => 'localnet'],
        );

        self::assertSame([
            'amount' => '1000',
            'currency' => 'USDC',
            'recipient' => 'recipient',
            'description' => 'Protected content',
            'externalId' => 'order-001',
            'methodDetails' => ['network' => 'localnet'],
        ], $request->toArray());
        self::assertEquals($request, ChargeRequest::fromArray($request->toArray()));
    }

    public function testOmitEmptyOptionalFields(): void
    {
        self::assertSame(
            ['amount' => '1', 'currency' => 'USDC'],
            (new ChargeRequest(amount: '1', currency: 'USDC'))->toArray(),
        );
    }

    public function testRejectsInvalidAmount(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('amount must be a positive base-unit integer string');

        new ChargeRequest(amount: '0', currency: 'USDC');
    }

    public function testRejectsLeadingZeroAmount(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('amount must be a positive base-unit integer string');

        new ChargeRequest(amount: '01000', currency: 'USDC');
    }

    public function testRejectsMissingCurrency(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('currency is required');

        new ChargeRequest(amount: '1000', currency: '');
    }

    public function testRejectsNonObjectMethodDetails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('methodDetails must be an object');

        ChargeRequest::fromArray([
            'amount' => '1000',
            'currency' => 'USDC',
            'methodDetails' => 'localnet',
        ]);
    }
}
