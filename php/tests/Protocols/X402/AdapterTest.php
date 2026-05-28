<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Price;
use PayKit\Protocols\X402\Adapter;
use PayKit\Protocols\X402\X402Config;
use PayKit\Signer;
use PHPUnit\Framework\TestCase;

final class AdapterTest extends TestCase
{
    private function makeConfig(?X402Config $x402 = null): Config
    {
        return new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer:    Signer::generate(),
                feePayer:  true,
            ),
            x402: $x402,
            preflight: false,
        );
    }

    public function testAcceptsEntryHasCanonicalX402Shape(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg, recentBlockhashProvider: fn () => 'BLOCKHASH-STUB');
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $entry = $adapter->acceptsEntry($gate, $req);
        $this->assertSame('x402', $entry['protocol']);
        $this->assertSame('exact', $entry['scheme']);
        $this->assertSame('100000', $entry['amount']);
        $this->assertSame('100000', $entry['maxAmountRequired']);
        $this->assertSame(60, $entry['maxTimeoutSeconds']);
        $this->assertSame('/paid', $entry['extra']['memo']);
        $this->assertSame(6, $entry['extra']['decimals']);
        $this->assertNotEmpty($entry['extra']['feePayer']);
    }

    public function testAcceptsEntryEmbedsRecentBlockhash(): void
    {
        // Ruby PR #142 caveat #5.
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg, recentBlockhashProvider: fn () => 'ABC123BLOCKHASH');
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $entry = $adapter->acceptsEntry($gate, $req);
        $this->assertSame('ABC123BLOCKHASH', $entry['extra']['recentBlockhash']);
    }

    public function testAcceptsEntryOmitsBlockhashWhenProviderReturnsNull(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg, recentBlockhashProvider: fn () => null);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $entry = $adapter->acceptsEntry($gate, $req);
        $this->assertArrayNotHasKey('recentBlockhash', $entry['extra']);
    }

    public function testChallengeHeadersAreBase64JsonEnvelope(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg, recentBlockhashProvider: fn () => null);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $headers = $adapter->challengeHeaders($gate, $req);
        $this->assertArrayHasKey('payment-required', $headers);
        $decoded = base64_decode($headers['payment-required'], true);
        $this->assertNotFalse($decoded);
        $envelope = json_decode($decoded, true);
        $this->assertSame(2, $envelope['x402Version']);
        $this->assertSame('/paid', $envelope['resource']['url']);
        $this->assertCount(1, $envelope['accepts']);
    }

    public function testDelegatedModeRejectedAtConstruction(): void
    {
        $cfg = $this->makeConfig(new X402Config(facilitatorUrl: 'https://facilitator.example.com'));
        $this->expectException(InvalidProofException::class);
        new Adapter($cfg);
    }

    public function testVerifyAndSettleRaisesWithoutPaymentSignature(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg, recentBlockhashProvider: fn () => null);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $this->expectException(InvalidProofException::class);
        $adapter->verifyAndSettle($gate, $req);
    }

    public function testVerifyAndSettleRaisesOnMalformedBase64(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg, recentBlockhashProvider: fn () => null);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid')
            ->withHeader('Payment-Signature', '@@@-not-base64-@@@');
        $this->expectException(InvalidProofException::class);
        $adapter->verifyAndSettle($gate, $req);
    }

    public function testVerifyAndSettleRaisesOnInvalidVersion(): void
    {
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg, recentBlockhashProvider: fn () => null);
        $gate = new Gate(amount: Price::usd('0.10'));
        $envelope = base64_encode(json_encode(['x402Version' => 99]) ?: '{}');
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid')
            ->withHeader('Payment-Signature', $envelope);
        $this->expectException(InvalidProofException::class);
        $adapter->verifyAndSettle($gate, $req);
    }
}
