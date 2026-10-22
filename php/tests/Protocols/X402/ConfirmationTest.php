<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Exception\SettlementInProgressException;
use PayKit\Operator;
use PayKit\Payment;
use PayKit\PayCore\Network;
use PayKit\Protocols\X402\Adapter;
use PayKit\Signer;
use PayKit\Tests\PayCore\Rpc\FakeRpcGateway;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use SolanaPhpSdk\Exception\RpcException;

/**
 * Confirm-before-success on the x402 exact adapter (main-audit finding 3)
 * and what an unconfirmed settlement answers.
 *
 * Only a reported on-chain failure rejects the payment
 * (InvalidProofException, a fresh 402). A status that cannot be read (an
 * RPC outage after the broadcast) or is not confirmed in time leaves it
 * pending (SettlementInProgressException, a retryable 409): the
 * transaction may already have landed, and a fresh challenge would let the
 * client pay twice.
 *
 * Building a fully-valid signed wire transaction for verifyAndSettle at
 * PHPUnit level is impractical, so these tests drive the private
 * broadcastAndConfirm step (broadcast, claim, confirm, authorize) via
 * reflection.
 */
final class ConfirmationTest extends TestCase
{
    private function makeAdapter(FakeRpcGateway $rpc, int $attempts = 3): Adapter
    {
        $config = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer: Signer::generate(),
                feePayer: true,
            ),
            preflight: false,
        );
        return new Adapter(
            $config,
            recentBlockhashProvider: fn () => null,
            rpc: $rpc,
            confirmationAttempts: $attempts,
            confirmationDelayMicros: 0,
        );
    }

    private function settle(Adapter $adapter): Payment
    {
        $method = new ReflectionMethod(Adapter::class, 'broadcastAndConfirm');
        $payment = $method->invoke($adapter, 'header', [], [], 2, 'wire');
        self::assertInstanceOf(Payment::class, $payment);
        return $payment;
    }

    public function testConfirmationReturnsWhenConfirmed(): void
    {
        $rpc = new FakeRpcGateway(signature: 'sigConfirmed');
        self::assertSame('sigConfirmed', $this->settle($this->makeAdapter($rpc))->transaction);
    }

    public function testConfirmationReturnsWhenFinalized(): void
    {
        $rpc = new FakeRpcGateway(
            signature: 'sigFinalized',
            statuses: [['err' => null, 'confirmationStatus' => 'finalized']],
        );
        self::assertSame('sigFinalized', $this->settle($this->makeAdapter($rpc))->transaction);
    }

    public function testNeverConfirmedLeavesThePaymentPending(): void
    {
        // RPC accepted the transaction but it only ever reaches
        // `processed`: no success, and no fresh challenge either.
        $rpc = new FakeRpcGateway(statuses: [['err' => null, 'confirmationStatus' => 'processed']]);
        $this->expectException(SettlementInProgressException::class);
        $this->expectExceptionMessageMatches('/Timed out waiting for transaction/');
        $this->settle($this->makeAdapter($rpc));
    }

    public function testUnknownStatusLeavesThePaymentPending(): void
    {
        $rpc = new FakeRpcGateway(statuses: [null]);
        $this->expectException(SettlementInProgressException::class);
        $this->expectExceptionMessageMatches('/Timed out waiting for transaction/');
        $this->settle($this->makeAdapter($rpc));
    }

    public function testStatusReadOutageLeavesThePaymentPending(): void
    {
        $outage = new RpcException('HTTP 503 from RPC', 503, -32099);
        $rpc = new FakeRpcGateway(statuses: [$outage]);
        $this->expectException(SettlementInProgressException::class);
        $this->expectExceptionMessageMatches('/HTTP 503 from RPC/');
        $this->settle($this->makeAdapter($rpc));
    }

    public function testStatusReadOutageThenConfirmedSettles(): void
    {
        $rpc = new FakeRpcGateway(
            signature: 'sigRecovered',
            statuses: [new RpcException('timeout', 0, -32099), ['err' => null, 'confirmationStatus' => 'confirmed']],
        );
        self::assertSame('sigRecovered', $this->settle($this->makeAdapter($rpc))->transaction);
    }

    public function testOnChainFailureRejectsThePayment(): void
    {
        // The transaction landed but failed on-chain (err set): definitive.
        $rpc = new FakeRpcGateway(
            statuses: [['err' => ['InstructionError' => [0, 'Custom']], 'confirmationStatus' => 'confirmed']],
        );
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/settlement not confirmed: Transaction .* failed/');
        $this->settle($this->makeAdapter($rpc));
    }
}
