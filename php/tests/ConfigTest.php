<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Config;
use PayKit\Exception\ConfigurationException;
use PayKit\Exception\DemoSignerOnMainnetException;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Protocol;
use PayKit\Signer;
use PayKit\PayCore\Stablecoin;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testZeroConfigUsesLocalnetDefaultsAndDemoSigner(): void
    {
        $cfg = new Config(preflight: false);
        $this->assertSame(Network::SolanaLocalnet, $cfg->network);
        $this->assertSame('https://402.surfnet.dev:8899', $cfg->rpcUrl);
        $this->assertTrue($cfg->operator->signer?->isDemo());
        // Recipient cascades to signer->pubkey().
        $this->assertSame(Signer::demo()->pubkey(), $cfg->effectiveRecipient());
    }

    public function testDevnetAndMainnetDefaults(): void
    {
        $cfg = new Config(network: Network::SolanaDevnet, preflight: false);
        $this->assertSame('https://api.devnet.solana.com', $cfg->rpcUrl);
    }

    public function testCustomRpcUrlHonoured(): void
    {
        $cfg = new Config(
            network: Network::SolanaDevnet,
            rpcUrl: 'https://my-helius.example.com',
            preflight: false,
        );
        $this->assertSame('https://my-helius.example.com', $cfg->rpcUrl);
    }

    public function testMainnetWithDemoSignerRejected(): void
    {
        $this->expectException(DemoSignerOnMainnetException::class);
        new Config(network: Network::SolanaMainnet, preflight: false);
    }

    public function testEmptyAcceptRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        new Config(accept: [], preflight: false);
    }

    public function testStablecoinAndAcceptOrderPreserved(): void
    {
        $cfg = new Config(
            accept:      [Protocol::Mpp, Protocol::X402],
            stablecoins: [Stablecoin::Usdt, Stablecoin::Usdc],
            preflight:   false,
        );
        $this->assertSame(Protocol::Mpp, $cfg->accept[0]);
        $this->assertSame(Stablecoin::Usdt, $cfg->stablecoins[0]);
    }

    public function testExplicitOperatorOverridesDefaults(): void
    {
        $sgn = Signer::generate();
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: 'CustomRecipient', signer: $sgn, feePayer: false),
            preflight: false,
        );
        $this->assertSame('CustomRecipient', $cfg->effectiveRecipient());
        $this->assertSame($sgn->pubkey(), $cfg->operator->signer?->pubkey());
        $this->assertFalse($cfg->operator->feePayer);
    }
    public function testEffectiveX402SignerFallsBackToOperatorSigner(): void
    {
        $sgn = Signer::generate();
        $cfg = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: $sgn, feePayer: true),
            preflight: false,
        );
        $this->assertSame($sgn->pubkey(), $cfg->effectiveX402Signer()?->pubkey());
    }

    public function testWithMppReturnsCopy(): void
    {
        $cfg = new Config(network: Network::SolanaDevnet, preflight: false);
        $newMpp = new \PayKit\Protocols\Mpp\MppConfig(realm: 'NewRealm', challengeBindingSecret: 'abc');
        $next = $cfg->withMpp($newMpp);
        $this->assertSame('NewRealm', $next->mpp->realm);
        $this->assertSame('abc', $next->mpp->challengeBindingSecret);
        $this->assertSame($cfg->network, $next->network);
    }

    public function testInvalidAcceptEntryRejected(): void
    {
        $this->expectException(\PayKit\Exception\ConfigurationException::class);
        new Config(accept: ['not-a-protocol-enum'], preflight: false);
    }

    public function testInvalidStablecoinEntryRejected(): void
    {
        $this->expectException(\PayKit\Exception\ConfigurationException::class);
        new Config(stablecoins: ['not-a-stablecoin-enum'], preflight: false);
    }

    public function testEmptyStablecoinsRejected(): void
    {
        $this->expectException(ConfigurationException::class);
        new Config(
            network: Network::SolanaDevnet,
            stablecoins: [],
            operator: new Operator(recipient: Signer::generate()->pubkey()),
            preflight: false,
            mpp: new \PayKit\Protocols\Mpp\MppConfig(challengeBindingSecret: 'x'),
        );
    }
}
