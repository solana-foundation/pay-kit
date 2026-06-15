<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Config;
use PayKit\Exception\ConfigurationException;
use PayKit\PayCore\Network;
use PayKit\PayCore\Stablecoin;
use PayKit\Operator;
use PayKit\Preflight;
use PayKit\Protocols\Mpp\MppConfig;
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

    public function testNoSignerCascadesToDemoAndRaisesOnDevnet(): void
    {
        Preflight::setRpcCallableForTests(function (string $m): mixed {
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
        $this->expectException(ConfigurationException::class);
        Preflight::run($cfg);
    }

    public function testAutofixFundsDemoFeePayerWhenBalanceLow(): void
    {
        $calls = [];
        Preflight::setRpcCallableForTests(function (string $m, array $params) use (&$calls): mixed {
            $calls[] = [$m, $params];
            return match ($m) {
                'getBalance'         => ['value' => 0],
                'getAccountInfo'     => ['value' => ['account-stub']],
                'surfnet_setAccount' => [],
                default              => null,
            };
        });

        $cfg = new Config(
            network: Network::SolanaLocalnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer: Signer::demo(),
                feePayer: true,
            ),
            preflight: true,
            stablecoins: [Stablecoin::Usdc],
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
        Preflight::run($cfg);

        $methods = array_column($calls, 0);
        $this->assertContains('getBalance', $methods);
        $this->assertContains('surfnet_setAccount', $methods);
    }

    public function testAutofixProvisionsRecipientAtaWhenMissing(): void
    {
        $calls = [];
        Preflight::setRpcCallableForTests(function (string $m, array $params) use (&$calls): mixed {
            $calls[] = [$m, $params];
            return match ($m) {
                'getBalance'              => ['value' => 100_000_000],
                // null .value triggers the autofix branch for ATA.
                'getAccountInfo'          => ['value' => null],
                'surfnet_setTokenAccount' => [],
                default                   => null,
            };
        });

        $cfg = new Config(
            network: Network::SolanaLocalnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer: Signer::demo(),
                feePayer: true,
            ),
            preflight: true,
            stablecoins: [Stablecoin::Usdc],
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
        Preflight::run($cfg);

        $methods = array_column($calls, 0);
        $this->assertContains('surfnet_setTokenAccount', $methods);
    }

    public function testDevnetMissingAtaWithoutAutofixRaises(): void
    {
        Preflight::setRpcCallableForTests(function (string $m): mixed {
            return match ($m) {
                'getBalance'     => ['value' => 100_000_000],
                'getAccountInfo' => ['value' => null],
                default          => null,
            };
        });
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer: Signer::generate(),
                feePayer: true,
            ),
            preflight: true,
            stablecoins: [Stablecoin::Usdc],
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
        $this->expectException(ConfigurationException::class);
        Preflight::run($cfg);
    }
}
