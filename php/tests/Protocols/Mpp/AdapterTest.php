<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\Mpp;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\Config;
use PayKit\PayCore\Currency;
use PayKit\Gate;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\Adapter;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Signer;
use PayKit\PayCore\Stablecoin;
use PHPUnit\Framework\TestCase;

final class AdapterTest extends TestCase
{
    private function makeConfig(): Config
    {
        return new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer:    Signer::generate(),
                feePayer:  true,
            ),
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'unit-test'),
        );
    }

    public function testAcceptsEntryShape(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $entry = $adapter->acceptsEntry($gate, $req);
        $this->assertSame('mpp', $entry['protocol']);
        $this->assertSame('charge', $entry['scheme']);
        $this->assertSame('100000', $entry['amount']);
        $this->assertSame('USDC', $entry['currency']);
        $this->assertSame($cfg->effectiveRecipient(), $entry['payTo']);
    }

    public function testAcceptsEntryIncludesSplitsForFeeBearingGate(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg);
        $platform = Signer::generate()->pubkey();
        $gate = new Gate(
            amount: Price::usd('10.00'),
            feeWithin: [$platform => Price::usd('0.30')],
        );
        $req = (new Psr17Factory())->createServerRequest('GET', '/marketplace');
        $entry = $adapter->acceptsEntry($gate, $req);
        $this->assertArrayHasKey('splits', $entry);
        $this->assertCount(1, $entry['splits']);
        $this->assertSame($platform, $entry['splits'][0]['recipient']);
        $this->assertSame('300000', $entry['splits'][0]['amount']);
    }

    public function testChallengeHeadersHaveWwwAuthenticate(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $headers = $adapter->challengeHeaders($gate, $req);
        $this->assertArrayHasKey('www-authenticate', $headers);
        $this->assertStringStartsWith('Payment ', $headers['www-authenticate']);
    }

    public function testVerifyAndSettleWithoutAuthorizationRaises(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $this->expectException(\PayKit\Exception\InvalidProofException::class);
        $adapter->verifyAndSettle($gate, $req);
    }
}
