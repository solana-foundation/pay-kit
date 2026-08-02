<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Upto;

use PayKit\Exception\InvalidProofException;
use PayKit\PayCore\PaymentChannels;
use PayKit\Protocols\X402\Upto\Types;
use PayKit\Protocols\X402\Upto\Verify;
use PHPUnit\Framework\TestCase;
use SolanaPhpSdk\Keypair\PublicKey;

/**
 * Offline pure-verifier coverage for x402 upto (payment-channel profile).
 * Mirrors python/tests/test_pk_x402_upto_verifier.py payload checks.
 */
final class VerifyTest extends TestCase
{
    private const MAX = 100_000;
    private const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

    public function testParseBaseUnitsOk(): void
    {
        self::assertSame(100000, Verify::parseBaseUnits('100000', 'amount'));
    }

    /** @dataProvider badBaseUnits */
    public function testParseBaseUnitsRejects(string $bad): void
    {
        $this->expectException(InvalidProofException::class);
        Verify::parseBaseUnits($bad, 'amount');
    }

    /** @return iterable<string, array{0: string}> */
    public static function badBaseUnits(): iterable
    {
        yield 'empty' => [''];
        yield 'alpha' => ['abc'];
        yield 'negative' => ['-1'];
        yield 'decimal' => ['1.5'];
        // Explicit decimal: u64_max+1 (not (string)(2**64) which is scientific).
        yield 'u64_overflow' => ['18446744073709551616'];
        // Above PHP_INT_MAX on 64-bit (still within u64) must not saturate.
        yield 'platform_overflow' => ['9223372036854775808'];
    }

    public function testParseStrictIntRejectsNonCanonical(): void
    {
        $this->expectException(InvalidProofException::class);
        Verify::parseStrictInt('123abc', 'validAfter');
    }

    public function testParseStrictIntAcceptsIntAndDigitString(): void
    {
        self::assertSame(42, Verify::parseStrictInt(42, 'validAfter'));
        self::assertSame(42, Verify::parseStrictInt('42', 'validAfter'));
        self::assertSame(-5, Verify::parseStrictInt('-5', 'expiresAt'));
    }

    public function testDecodeOpenArgsRejectsTrailingBytes(): void
    {
        $data = PaymentChannels::encodeOpenInstructionData(7, self::MAX, 900, 4242);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('trailing bytes');
        PaymentChannels::decodeOpenArgs($data . "\x00");
    }

    public function testDecodeOpenArgsRejectsNonEmptyRecipients(): void
    {
        // Build open data with recipients_len = 1 and no body → too short for
        // entries, but decode rejects non-zero len before reading entries.
        $base = PaymentChannels::encodeOpenInstructionData(7, self::MAX, 900, 4242);
        // Last 4 bytes are recipients_len=0; rewrite to 1.
        $data = substr($base, 0, 29) . "\x01\x00\x00\x00";
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('recipients length must be 0');
        PaymentChannels::decodeOpenArgs($data);
    }

    public function testValidateOpenInstructionRequiresExactly14Accounts(): void
    {
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('exactly 14 accounts');
        $program = new PublicKey(PaymentChannels::PROGRAM_ID);
        // 13 dummy static keys + program id at the end (programIdIndex = 13).
        $keys = [];
        for ($i = 1; $i <= 13; $i++) {
            $keys[] = (string) new PublicKey(str_repeat(chr($i), 32));
        }
        $keys[] = (string) $program;
        // Only 13 account metas — triggers the fixed-layout check.
        Verify::validateUptoOpenInstruction(
            $keys,
            [[
                'programIdIndex' => 13,
                'accounts'       => range(0, 12),
                'data'           => PaymentChannels::encodeOpenInstructionData(1, self::MAX, 900, 1),
            ]],
            $program,
            new PublicKey($keys[1]),
            new PublicKey($keys[4]),
            new PublicKey($keys[0]),
            new PublicKey($keys[2]),
            new PublicKey($keys[3]),
            new PublicKey($keys[8]),
            new PublicKey($keys[5]),
            self::MAX,
            900,
            '1',
            '1',
            null,
        );
    }

    public function testVerifyUptoPayloadOk(): void
    {
        $operator = $this->operatorPubkey();
        $now = time();
        Verify::verifyUptoPayload(
            $this->payload($operator, $now),
            $this->requirements($operator),
            $operator,
            $now,
        );
        $this->addToAssertionCount(1);
    }

    public function testVerifyUptoPayloadRejectsAmountMismatch(): void
    {
        $operator = $this->operatorPubkey();
        $now = time();
        $payload = $this->payload($operator, $now);
        $payload['maxAmount'] = '1';
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('amount mismatch');
        Verify::verifyUptoPayload($payload, $this->requirements($operator), $operator, $now);
    }

    public function testVerifyUptoPayloadRejectsDepositMismatch(): void
    {
        $operator = $this->operatorPubkey();
        $now = time();
        $payload = $this->payload($operator, $now);
        $payload['deposit'] = '1';
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('channel deposit');
        Verify::verifyUptoPayload($payload, $this->requirements($operator), $operator, $now);
    }

    public function testVerifyUptoPayloadRejectsExpired(): void
    {
        $operator = $this->operatorPubkey();
        $now = time();
        $payload = $this->payload($operator, $now);
        $payload['expiresAt'] = $now - 1;
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('authorization expired');
        Verify::verifyUptoPayload($payload, $this->requirements($operator), $operator, $now);
    }

    public function testVerifyUptoPayloadRejectsNotYetActive(): void
    {
        $operator = $this->operatorPubkey();
        $now = time();
        $payload = $this->payload($operator, $now);
        $payload['validAfter'] = $now + 60;
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('not yet active');
        Verify::verifyUptoPayload($payload, $this->requirements($operator), $operator, $now);
    }

    public function testVerifyUptoPayloadRejectsWrongAuthorizer(): void
    {
        $operator = $this->operatorPubkey();
        $now = time();
        $payload = $this->payload($operator, $now);
        $payload['authorizedSigner'] = '11111111111111111111111111111112';
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage('authorized_signer');
        Verify::verifyUptoPayload($payload, $this->requirements($operator), $operator, $now);
    }

    public function testAssertSettlementWithinCeiling(): void
    {
        Verify::assertSettlementWithinCeiling(50_000, self::MAX);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessage(Types::ERROR_SETTLEMENT_EXCEEDS_AMOUNT);
        Verify::assertSettlementWithinCeiling(self::MAX + 1, self::MAX);
    }

    public function testVoucherMessageBytesLayout(): void
    {
        $channel = new PublicKey(str_repeat("\x09", 32));
        $got = PaymentChannels::voucherMessageBytes($channel, 42, 1234);
        self::assertSame(50, strlen($got));
        self::assertSame("\x56\x01", substr($got, 0, 2));
        self::assertSame($channel->toBytes(), substr($got, 2, 32));
        self::assertSame($this->leU64(42), substr($got, 34, 8));
        self::assertSame($this->leI64(1234), substr($got, 42, 8));
    }

    public function testVoucherMessageBytesNegativeExpires(): void
    {
        $channel = new PublicKey(str_repeat("\x03", 32));
        $got = PaymentChannels::voucherMessageBytes($channel, 7, -5);
        self::assertSame(50, strlen($got));
        self::assertSame($this->leI64(-5), substr($got, 42, 8));
    }

    public function testChannelPdaDeterministic(): void
    {
        $payer = new PublicKey(str_repeat("\x01", 32));
        $payee = new PublicKey(str_repeat("\x02", 32));
        $mint = new PublicKey(str_repeat("\x03", 32));
        $signer = new PublicKey(str_repeat("\x04", 32));
        [$a, $bumpA] = PaymentChannels::findChannelPda($payer, $payee, $mint, $signer, 99, 55_555);
        [$b, $bumpB] = PaymentChannels::findChannelPda($payer, $payee, $mint, $signer, 99, 55_555);
        self::assertTrue($a->equals($b));
        self::assertSame($bumpA, $bumpB);
        // Different openSlot → different channel.
        [$c] = PaymentChannels::findChannelPda($payer, $payee, $mint, $signer, 99, 55_556);
        self::assertFalse($a->equals($c));
    }

    public function testEncodeDecodeOpenArgsRoundTrip(): void
    {
        $data = PaymentChannels::encodeOpenInstructionData(7, self::MAX, 900, 4242);
        $args = PaymentChannels::decodeOpenArgs($data);
        self::assertSame(7, $args['salt']);
        self::assertSame(self::MAX, $args['deposit']);
        self::assertSame(900, $args['gracePeriod']);
        self::assertSame(4242, $args['openSlot']);
    }

    /** @return array<string,mixed> */
    private function requirements(string $operator): array
    {
        return [
            'scheme'            => Types::SCHEME,
            'network'           => 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
            'amount'            => (string) self::MAX,
            'asset'             => self::MINT,
            'payTo'             => $operator,
            'maxTimeoutSeconds' => 300,
            'extra'             => [
                'decimals'           => 6,
                'tokenProgram'       => PaymentChannels::tokenProgramId(),
                'feePayer'           => $operator,
                'receiverAuthorizer' => $operator,
                'withdrawDelay'      => 900,
                'recentBlockhash'    => '4vJ9JU1bJJQpUgJ8V6hYz7xXKz4F2tN6aBrZEcD3xKhs',
                'recentSlot'         => '4242',
            ],
        ];
    }

    /** @return array<string,mixed> */
    private function payload(string $operator, int $now): array
    {
        return [
            'from'             => (string) new PublicKey(str_repeat("\x11", 32)),
            'maxAmount'        => (string) self::MAX,
            'expiresAt'        => $now + 300,
            'validAfter'       => $now - 10,
            'nonce'            => '7',
            'channelId'        => '11111111111111111111111111111112',
            'deposit'          => (string) self::MAX,
            'authorizedSigner' => $operator,
            'openSlot'         => '4242',
        ];
    }

    private function operatorPubkey(): string
    {
        return (string) new PublicKey(str_repeat("\x0A", 32));
    }

    private function leU64(int $value): string
    {
        $out = '';
        for ($i = 0; $i < 8; $i++) {
            $out .= chr(($value >> ($i * 8)) & 0xFF);
        }

        return $out;
    }

    private function leI64(int $value): string
    {
        return $this->leU64($value);
    }
}
