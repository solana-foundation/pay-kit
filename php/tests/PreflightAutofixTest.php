<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Config;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Preflight;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Signer;
use PayKit\PayCore\Stablecoin;
use PHPUnit\Framework\TestCase;

/**
 * Drives the autofix branches of Preflight (only fires when network
 * is SolanaLocalnet AND operator signer is the demo singleton).
 */
final class PreflightAutofixTest extends TestCase
{
    protected function tearDown(): void
    {
        Preflight::setRpcCallableForTests(null);
    }

    public function testAutofixFundsDemoFeePayerWhenBalanceLow(): void
    {
        $calls = [];
        Preflight::setRpcCallableForTests(function (string $m, array $params) use (&$calls): mixed {
            $calls[] = [$m, $params];
            return match ($m) {
                'getBalance'             => ['value' => 0],
                'getAccountInfo'         => ['value' => ['account-stub']],
                'surfnet_setAccount'     => [],
                default                  => null,
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
        $this->expectException(\PayKit\Exception\ConfigurationException::class);
        Preflight::run($cfg);
    }
}
