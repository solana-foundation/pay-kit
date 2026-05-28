<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Config;
use PayKit\Exception\ConfigurationException;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Preflight;
use PayKit\Signer;
use PHPUnit\Framework\TestCase;

final class PreflightTest extends TestCase
{
    protected function tearDown(): void
    {
        Preflight::setRpcCallableForTests(null);
    }

    public function testDisabledByEnvVarShortCircuit(): void
    {
        $prev = getenv('PAY_KIT_DISABLE_PREFLIGHT');
        putenv('PAY_KIT_DISABLE_PREFLIGHT=1');
        try {
            $this->assertTrue(Preflight::isDisabledByEnv());
        } finally {
            putenv($prev === false ? 'PAY_KIT_DISABLE_PREFLIGHT' : 'PAY_KIT_DISABLE_PREFLIGHT=' . $prev);
        }
    }

    public function testLowBalanceRaisesOffLocalnet(): void
    {
        Preflight::setRpcCallableForTests(function (string $method, array $params): mixed {
            return match ($method) {
                'getBalance'     => ['value' => 1],
                'getAccountInfo' => ['value' => []],
                default          => null,
            };
        });
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
            preflight: false,
        );
        $this->expectException(ConfigurationException::class);
        Preflight::run($cfg);
    }

    public function testMissingAtaRaisesOffLocalnet(): void
    {
        Preflight::setRpcCallableForTests(function (string $method, array $params): mixed {
            return match ($method) {
                'getBalance'     => ['value' => 1_000_000_000],
                'getAccountInfo' => ['value' => null],
                default          => null,
            };
        });
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
            preflight: false,
        );
        $this->expectException(ConfigurationException::class);
        Preflight::run($cfg);
    }

    public function testLocalnetDemoAutoFunds(): void
    {
        $funded = false;
        Preflight::setRpcCallableForTests(function (string $method, array $params) use (&$funded): mixed {
            return match ($method) {
                'getBalance'              => ['value' => 1],
                'getAccountInfo'          => ['value' => []],
                'surfnet_setAccount'      => $funded = true,
                'surfnet_setTokenAccount' => null,
                default                   => null,
            };
        });
        $cfg = new Config(
            network: Network::SolanaLocalnet,
            preflight: false, // we'll invoke Preflight::run manually
        );
        Preflight::run($cfg);
        $this->assertTrue($funded);
    }

    public function testRpcFailureDowngradedToWarning(): void
    {
        Preflight::setRpcCallableForTests(function (string $method, array $params): mixed {
            throw new \RuntimeException('rpc unreachable');
        });
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
            preflight: false,
        );
        // Must not raise.
        Preflight::run($cfg);
        $this->assertTrue(true);
    }
}
