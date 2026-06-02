<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402;

use PayKit\Config;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\Protocols\X402\Adapter;
use PayKit\Signer;
use PayKit\Tests\PayCore\Rpc\FakeRpcGateway;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * Regression coverage for main-audit finding 3: the x402 exact adapter
 * MUST confirm the broadcast transaction before returning a success
 * payment-response. Previously it returned success on RPC acceptance
 * alone, so a transaction that RPC accepted but never finalized (or
 * later failed) still produced a success header.
 *
 * Building a fully-valid signed Solana wire transaction at PHPUnit level
 * is impractical (the structural verifier and cosign step run before
 * confirmation), so these tests exercise the private awaitConfirmation
 * gate directly via reflection. The gate is the load-bearing
 * confirm-before-success primitive; verifyAndSettle calls it on the
 * broadcast signature before composing the success envelope.
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

    private function invokeAwaitConfirmation(Adapter $adapter, string $signature): void
    {
        $method = new ReflectionMethod(Adapter::class, 'awaitConfirmation');
        $method->setAccessible(true);
        $method->invoke($adapter, $signature);
    }

    public function testConfirmationReturnsWhenConfirmed(): void
    {
        $rpc = new FakeRpcGateway(
            statuses: [['err' => null, 'confirmationStatus' => 'confirmed']],
        );
        $adapter = $this->makeAdapter($rpc);
        // No exception means the confirm gate passed.
        $this->invokeAwaitConfirmation($adapter, 'sigConfirmed');
        $this->addToAssertionCount(1);
    }

    public function testConfirmationReturnsWhenFinalized(): void
    {
        $rpc = new FakeRpcGateway(
            statuses: [['err' => null, 'confirmationStatus' => 'finalized']],
        );
        $adapter = $this->makeAdapter($rpc);
        $this->invokeAwaitConfirmation($adapter, 'sigFinalized');
        $this->addToAssertionCount(1);
    }

    public function testConfirmationTimesOutWhenNeverConfirmed(): void
    {
        // RPC accepted the transaction but it only ever reaches
        // `processed`; the gate must throw rather than report success.
        $rpc = new FakeRpcGateway(
            statuses: [['err' => null, 'confirmationStatus' => 'processed']],
        );
        $adapter = $this->makeAdapter($rpc, attempts: 3);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Timed out waiting for transaction/');
        $this->invokeAwaitConfirmation($adapter, 'sigStuck');
    }

    public function testConfirmationTimesOutWhenStatusAlwaysNull(): void
    {
        // getSignatureStatuses returns null entries (signature unknown to
        // the cluster) for the whole budget. Must throw, not succeed.
        $rpc = new FakeRpcGateway(statuses: [null]);
        $adapter = $this->makeAdapter($rpc, attempts: 3);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/Timed out waiting for transaction/');
        $this->invokeAwaitConfirmation($adapter, 'sigUnknown');
    }

    public function testConfirmationThrowsOnOnChainFailure(): void
    {
        // The transaction landed but failed on-chain (err set). Must throw
        // so no success header is emitted for a reverted transfer.
        $rpc = new FakeRpcGateway(
            statuses: [['err' => ['InstructionError' => [0, 'Custom']], 'confirmationStatus' => 'confirmed']],
        );
        $adapter = $this->makeAdapter($rpc);
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/failed/');
        $this->invokeAwaitConfirmation($adapter, 'sigFailed');
    }
}
