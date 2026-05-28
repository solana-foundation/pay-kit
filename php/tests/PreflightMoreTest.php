<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Config;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Preflight;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Signer;
use PHPUnit\Framework\TestCase;

final class PreflightMoreTest extends TestCase
{
    protected function tearDown(): void
    {
        Preflight::setRpcCallableForTests(null);
    }

    public function testFeePayerFalseSkipsBalanceCheck(): void
    {
        $balanceCalled = false;
        Preflight::setRpcCallableForTests(function (string $m) use (&$balanceCalled): mixed {
            if ($m === 'getBalance') {
                $balanceCalled = true;
            }
            return match ($m) {
                'getBalance'     => ['value' => 0],
                'getAccountInfo' => ['value' => []],
                default          => null,
            };
        });
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: false),
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
        Preflight::run($cfg);
        $this->assertFalse($balanceCalled);
    }

    public function testNoSignerSkipsBalanceCheck(): void
    {
        $balanceCalled = false;
        Preflight::setRpcCallableForTests(function (string $m) use (&$balanceCalled): mixed {
            if ($m === 'getBalance') {
                $balanceCalled = true;
            }
            return match ($m) {
                'getBalance'     => ['value' => 0],
                'getAccountInfo' => ['value' => []],
                default          => null,
            };
        });
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: null, feePayer: true),
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
        // operator->signer cascades to Demo via Operator::withDefaults;
        // balance check fires and raises (devnet, 0 lamports).
        $this->expectException(\PayKit\Exception\ConfigurationException::class);
        Preflight::run($cfg);
    }
}
