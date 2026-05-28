<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Client;
use PayKit\Config;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Preflight;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Signer;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    protected function tearDown(): void
    {
        Preflight::setRpcCallableForTests(null);
    }

    public function testHoldsConfigAfterBoot(): void
    {
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
        $client = new Client($cfg);
        $this->assertSame($cfg, $client->config);
    }

    public function testRunsPreflightWhenEnabled(): void
    {
        $called = false;
        Preflight::setRpcCallableForTests(function (string $m) use (&$called): mixed {
            $called = true;
            return match ($m) {
                'getBalance'              => ['value' => 1_000_000_000],
                'getAccountInfo'          => ['value' => []],
                'surfnet_setAccount'      => [],
                'surfnet_setTokenAccount' => [],
                default                   => null,
            };
        });
        $cfg = new Config(
            network: Network::SolanaLocalnet,
            preflight: true,
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
        new Client($cfg);
        $this->assertTrue($called);
    }

    public function testSkipsPreflightWhenEnvDisabled(): void
    {
        $prev = getenv('PAY_KIT_DISABLE_PREFLIGHT');
        putenv('PAY_KIT_DISABLE_PREFLIGHT=1');
        try {
            $called = false;
            Preflight::setRpcCallableForTests(function () use (&$called) {
                $called = true;
                return null;
            });
            new Client(new Config(
                network: Network::SolanaLocalnet,
                preflight: true,
                mpp: new MppConfig(challengeBindingSecret: 'x'),
            ));
            $this->assertFalse($called);
        } finally {
            putenv($prev === false ? 'PAY_KIT_DISABLE_PREFLIGHT' : 'PAY_KIT_DISABLE_PREFLIGHT=' . $prev);
        }
    }
}
