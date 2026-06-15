<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402;

use PayKit\Protocols\X402\Exact\PaymentExtensions;
use PayKit\Protocols\X402\Exact\PaymentIdentifierExtension;
use PayKit\Protocols\X402\Exact\PaymentIdentifierInfo;
use PHPUnit\Framework\TestCase;

final class PaymentExtensionsTest extends TestCase
{
    public function testInfoFromArrayReadsTypedFields(): void
    {
        $info = PaymentIdentifierInfo::fromArray(['required' => true, 'id' => 'pay_0123456789abcdef']);
        self::assertTrue($info->required);
        self::assertSame('pay_0123456789abcdef', $info->id);
    }

    public function testInfoFromArrayIgnoresWrongTypes(): void
    {
        $info = PaymentIdentifierInfo::fromArray(['required' => 'yes', 'id' => 123]);
        self::assertNull($info->required);
        self::assertNull($info->id);
    }

    public function testInfoHasValidId(): void
    {
        self::assertTrue((new PaymentIdentifierInfo(id: 'pay_0123456789abcdef'))->hasValidId());
        self::assertTrue((new PaymentIdentifierInfo(id: '0123456789abcdef'))->hasValidId()); // exactly 16
        self::assertFalse((new PaymentIdentifierInfo(id: 'short'))->hasValidId());
        self::assertFalse((new PaymentIdentifierInfo(id: 'pay_with space!'))->hasValidId());
        self::assertFalse((new PaymentIdentifierInfo(id: ''))->hasValidId());
        self::assertFalse((new PaymentIdentifierInfo())->hasValidId());
    }

    public function testInfoToArrayOmitsNulls(): void
    {
        self::assertSame([], (new PaymentIdentifierInfo())->toArray());
        self::assertSame(['required' => true], (new PaymentIdentifierInfo(required: true))->toArray());
        self::assertSame(
            ['required' => false, 'id' => 'pay_0123456789abcdef'],
            (new PaymentIdentifierInfo(required: false, id: 'pay_0123456789abcdef'))->toArray(),
        );
    }

    public function testExtensionFromArrayAndToArray(): void
    {
        $ext = PaymentIdentifierExtension::fromArray([
            'info' => ['required' => true],
            'schema' => ['type' => 'string'],
        ]);
        self::assertTrue($ext->info->required);
        self::assertSame(['type' => 'string'], $ext->schema);
        self::assertSame(
            ['info' => ['required' => true], 'schema' => ['type' => 'string']],
            $ext->toArray(),
        );
    }

    public function testExtensionFromArrayDefaultsInfoAndOmitsNullSchema(): void
    {
        $ext = PaymentIdentifierExtension::fromArray(['info' => 'not-an-array']);
        self::assertNull($ext->info->required);
        self::assertSame(['info' => []], $ext->toArray()); // schema omitted when null
    }

    public function testEchoingNullReturnsNull(): void
    {
        self::assertNull(PaymentExtensions::echoing(null));
        self::assertNull(PaymentExtensions::fromArray(null));
    }

    public function testEchoingSplitsPaymentIdentifierAndPreservesUnknownVerbatim(): void
    {
        $ext = PaymentExtensions::echoing([
            PaymentExtensions::PAYMENT_IDENTIFIER_KEY => ['info' => ['required' => true]],
            'future-extension' => ['keep' => true],
            'malformed-pi-ignored' => 'scalar',
        ]);
        self::assertNotNull($ext);
        self::assertTrue($ext->requiresPaymentIdentifier());
        self::assertSame(['keep' => true], $ext->other['future-extension']);
        self::assertSame('scalar', $ext->other['malformed-pi-ignored']);
    }

    public function testEchoingNonArrayPaymentIdentifierYieldsNullEntry(): void
    {
        $ext = PaymentExtensions::echoing([PaymentExtensions::PAYMENT_IDENTIFIER_KEY => 'scalar']);
        self::assertNotNull($ext);
        self::assertFalse($ext->requiresPaymentIdentifier());
    }

    public function testIsEmpty(): void
    {
        self::assertTrue((new PaymentExtensions())->isEmpty());
        self::assertFalse((new PaymentExtensions(paymentIdentifier: new PaymentIdentifierExtension()))->isEmpty());
        self::assertFalse((new PaymentExtensions(other: ['x' => 1]))->isEmpty());
    }

    public function testRequiresPaymentIdentifier(): void
    {
        self::assertFalse((new PaymentExtensions())->requiresPaymentIdentifier());
        self::assertFalse((new PaymentExtensions(
            paymentIdentifier: new PaymentIdentifierExtension(info: new PaymentIdentifierInfo(required: false)),
        ))->requiresPaymentIdentifier());
        self::assertTrue((new PaymentExtensions(
            paymentIdentifier: new PaymentIdentifierExtension(info: new PaymentIdentifierInfo(required: true)),
        ))->requiresPaymentIdentifier());
    }

    public function testWithPaymentIdentifierIdCreatesEntryAndPreservesServerFields(): void
    {
        // Creates the entry when the server advertised none.
        $created = (new PaymentExtensions())->withPaymentIdentifierId('pay_0123456789abcdef');
        self::assertSame('pay_0123456789abcdef', $created->paymentIdentifier?->info->id);

        // Preserves server-side required + schema when filling the id.
        $advertised = new PaymentExtensions(
            paymentIdentifier: new PaymentIdentifierExtension(
                info: new PaymentIdentifierInfo(required: true),
                schema: ['type' => 'string'],
            ),
        );
        $filled = $advertised->withPaymentIdentifierId('pay_abcdef0123456789');
        self::assertTrue($filled->requiresPaymentIdentifier());
        self::assertSame('pay_abcdef0123456789', $filled->paymentIdentifier?->info->id);
        self::assertSame(['type' => 'string'], $filled->paymentIdentifier?->schema);
    }

    public function testToArrayEmitsKebabKeyAndFlattensUnknown(): void
    {
        $ext = new PaymentExtensions(
            paymentIdentifier: new PaymentIdentifierExtension(info: new PaymentIdentifierInfo(required: true)),
            other: ['future-extension' => ['keep' => true]],
        );
        $arr = $ext->toArray();
        self::assertArrayHasKey('payment-identifier', $arr);
        self::assertArrayNotHasKey('paymentIdentifier', $arr);
        self::assertSame(['info' => ['required' => true]], $arr['payment-identifier']);
        self::assertSame(['keep' => true], $arr['future-extension']);
    }

    public function testGeneratePaymentIdentifierId(): void
    {
        $id = PaymentExtensions::generatePaymentIdentifierId();
        self::assertSame(36, strlen($id));
        self::assertStringStartsWith('pay_', $id);
        self::assertSame(1, preg_match(PaymentIdentifierInfo::ID_PATTERN, $id));
        self::assertNotSame($id, PaymentExtensions::generatePaymentIdentifierId());
    }
}
