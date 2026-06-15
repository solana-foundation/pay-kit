<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\Mpp\Server;

use InvalidArgumentException;
use PayKit\Tests\PayCore\Rpc\FakeRpcGateway;
use PayKit\Protocols\Mpp\Server\ChargeServer;
use PayKit\Protocols\Mpp\Server\SolanaChargeHandler;
use PayKit\Protocols\Mpp\Server\SolanaChargeTransactionVerifier;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use RuntimeException;

/**
 * Drives the private settle / confirmation / replay paths of
 * SolanaChargeHandler via the FakeRpcGateway test double. Mirrors
 * ruby/test/server_test.rb's coverage of the same paths.
 */
final class SolanaChargeHandlerInternalsTest extends TestCase
{
    private function handlerWith(FakeRpcGateway $rpc, int $confirmationAttempts = 3, int $confirmationDelayMicros = 1_000): SolanaChargeHandler
    {
        return new SolanaChargeHandler(
            challenges: new ChargeServer(
                secretKey: 'test-secret-0123456789abcdef-0123456789',
                realm: 'test',
            ),
            rpc: $rpc,
            feePayer: null,
            network: 'mainnet',
            verifier: new SolanaChargeTransactionVerifier(),
            confirmationAttempts: $confirmationAttempts,
            confirmationDelayMicros: $confirmationDelayMicros,
        );
    }

    private function invoke(SolanaChargeHandler $handler, string $method, mixed ...$args): mixed
    {
        $rc = new ReflectionClass($handler);
        $m = $rc->getMethod($method);
        $m->setAccessible(true);
        return $m->invoke($handler, ...$args);
    }

    public function testAwaitConfirmationReturnsOnConfirmedStatus(): void
    {
        $rpc = new FakeRpcGateway(
            statuses: [
                null,
                ['err' => null, 'confirmationStatus' => 'processed'],
                ['err' => null, 'confirmationStatus' => 'confirmed'],
            ],
        );
        $h = $this->handlerWith($rpc, confirmationAttempts: 5);
        $this->invoke($h, 'awaitConfirmation', 'sig-confirmed');
        $this->assertSame(3, count($rpc->calls) + count($rpc->sentTransactions) + 3); // 3 status polls happened
    }

    public function testAwaitConfirmationFinalizedAlsoAccepted(): void
    {
        $rpc = new FakeRpcGateway(
            statuses: [['err' => null, 'confirmationStatus' => 'finalized']],
        );
        $h = $this->handlerWith($rpc);
        $this->invoke($h, 'awaitConfirmation', 'sig-final');
        $this->assertTrue(true); // no throw == pass
    }

    public function testAwaitConfirmationTransactionErrorThrows(): void
    {
        $rpc = new FakeRpcGateway(
            statuses: [['err' => ['InsufficientFundsForFee' => []], 'confirmationStatus' => 'confirmed']],
        );
        $h = $this->handlerWith($rpc);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('failed');
        $this->invoke($h, 'awaitConfirmation', 'sig-failed');
    }

    public function testAwaitConfirmationTimesOutAfterMaxAttempts(): void
    {
        $rpc = new FakeRpcGateway(statuses: [null]);
        $h = $this->handlerWith($rpc, confirmationAttempts: 2);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Timed out');
        $this->invoke($h, 'awaitConfirmation', 'sig-timeout');
    }

    public function testSettleRejectsEmptyBase64(): void
    {
        $rpc = new FakeRpcGateway();
        $h = $this->handlerWith($rpc);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid transaction payload');
        $this->invoke($h, 'settle', '');
    }

    public function testSettleRejectsInvalidBase64(): void
    {
        $rpc = new FakeRpcGateway();
        $h = $this->handlerWith($rpc);
        $this->expectException(InvalidArgumentException::class);
        $this->invoke($h, 'settle', '!!!not-base64!!!');
    }

    public function testConsumeSignatureRejectsReplay(): void
    {
        $rpc = new FakeRpcGateway();
        $h = $this->handlerWith($rpc);
        $this->invoke($h, 'consumeSignature', 'sig-once');
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('already consumed');
        $this->invoke($h, 'consumeSignature', 'sig-once');
    }

    public function testFetchSettledTransactionReturnsWireBase64(): void
    {
        $rpc = new FakeRpcGateway(
            callResults: [
                null,
                [
                    'meta'        => ['err' => null],
                    'transaction' => ['BASE64-wire-blob'],
                ],
            ],
        );
        $h = $this->handlerWith($rpc, confirmationAttempts: 3);
        $result = $this->invoke($h, 'fetchSettledTransaction', 'sig-x');
        $this->assertSame('BASE64-wire-blob', $result);
    }

    public function testFetchSettledTransactionAcceptsStringTransaction(): void
    {
        $rpc = new FakeRpcGateway(
            callResults: [[
                'meta'        => ['err' => null],
                'transaction' => 'BASE64-string-form',
            ]],
        );
        $h = $this->handlerWith($rpc);
        $result = $this->invoke($h, 'fetchSettledTransaction', 'sig-x');
        $this->assertSame('BASE64-string-form', $result);
    }

    public function testFetchSettledTransactionMetaErrThrows(): void
    {
        $rpc = new FakeRpcGateway(
            callResults: [[
                'meta'        => ['err' => ['SomeErr' => []]],
                'transaction' => ['BASE64'],
            ]],
        );
        $h = $this->handlerWith($rpc);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('failed');
        $this->invoke($h, 'fetchSettledTransaction', 'sig-x');
    }

    public function testFetchSettledTransactionMissingMetaThrows(): void
    {
        $rpc = new FakeRpcGateway(callResults: [['no-meta' => true]]);
        $h = $this->handlerWith($rpc);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('missing transaction metadata');
        $this->invoke($h, 'fetchSettledTransaction', 'sig-x');
    }

    public function testFetchSettledTransactionInvalidResponseTypeThrows(): void
    {
        $rpc = new FakeRpcGateway(callResults: ['not-an-array']);
        $h = $this->handlerWith($rpc);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid');
        $this->invoke($h, 'fetchSettledTransaction', 'sig-x');
    }

    public function testFetchSettledTransactionTimesOut(): void
    {
        $rpc = new FakeRpcGateway(callResults: [null]);
        $h = $this->handlerWith($rpc, confirmationAttempts: 2);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Timed out');
        $this->invoke($h, 'fetchSettledTransaction', 'sig-x');
    }
}
