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

    public function testChargeRequestAmountIsGateTotalForFeeOnTop(): void
    {
        // Regression: chargeRequestFor pinned the bare base amount while
        // acceptsEntry advertised the total, so a fee-on-top gate issued a
        // challenge short by the on-top fee. The MPP wire derives the primary
        // share as amount - sum(splits), so the merchant was undercharged the
        // fee. The expected (and issued) charge request must use gate->total().
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg);
        $platform = Signer::generate()->pubkey();
        $gate = new Gate(
            amount: Price::usd('10.00'),
            feeOnTop: [$platform => Price::usd('0.30')],
        );

        $method = new \ReflectionMethod($adapter, 'chargeRequestFor');
        $method->setAccessible(true);
        $chargeRequest = $method->invoke($adapter, $gate);

        // 10.00 base + 0.30 on top = 10.30 USDC = 10_300_000 micro-units.
        $this->assertSame('10300000', $chargeRequest->amount);

        // acceptsEntry already advertised the total; the two must agree.
        $req = (new Psr17Factory())->createServerRequest('GET', '/marketplace');
        $entry = $adapter->acceptsEntry($gate, $req);
        $this->assertSame('10300000', $entry['amount']);
    }

    public function testChargeRequestAmountUnchangedForFeeWithin(): void
    {
        // fee-within gates keep total == base, so the total switch is a no-op.
        $cfg = $this->makeConfig();
        $adapter = new Adapter($cfg);
        $platform = Signer::generate()->pubkey();
        $gate = new Gate(
            amount: Price::usd('10.00'),
            feeWithin: [$platform => Price::usd('0.30')],
        );

        $method = new \ReflectionMethod($adapter, 'chargeRequestFor');
        $method->setAccessible(true);
        $chargeRequest = $method->invoke($adapter, $gate);

        $this->assertSame('10000000', $chargeRequest->amount);
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

    private function makeConfigWithExpiresIn(int $expiresIn): Config
    {
        return new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer:    Signer::generate(),
                feePayer:  true,
            ),
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'unit-test', expiresIn: $expiresIn),
        );
    }

    public function testChallengeWiresMppExpiresIntoIssuance(): void
    {
        // main-audit finding 7: config.mpp.expiresIn must thread into every
        // issued challenge as an RFC 3339 expires. Previously the adapter
        // issued challenges with no expiry, so they never expired.
        $cfg = $this->makeConfigWithExpiresIn(120);
        $adapter = new Adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');

        $headers = $adapter->challengeHeaders($gate, $req);
        $challenge = \PayKit\Protocols\Mpp\Core\Headers::parseWwwAuthenticate($headers['www-authenticate']);

        $this->assertNotSame('', $challenge->expires, 'challenge must carry an expires when expiresIn > 0');
        $parsed = \PayKit\PayCore\Rfc3339Parser::parse($challenge->expires);
        $this->assertNotNull($parsed, 'expires must be valid RFC 3339');
        // ~120s in the future (allow generous slack for slow CI).
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $deltaSeconds = $parsed->getTimestamp() - $now->getTimestamp();
        $this->assertGreaterThan(60, $deltaSeconds);
        $this->assertLessThanOrEqual(121, $deltaSeconds);
        // A freshly-issued 120s challenge is not yet expired.
        $this->assertFalse($challenge->isExpired($now));
    }

    public function testChallengeIsRejectedAfterExpiryWindow(): void
    {
        // The wired expiry must actually drive isExpired(): a challenge
        // issued with a short TTL is expired once that window elapses.
        $cfg = $this->makeConfigWithExpiresIn(1);
        $adapter = new Adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');

        $headers = $adapter->challengeHeaders($gate, $req);
        $challenge = \PayKit\Protocols\Mpp\Core\Headers::parseWwwAuthenticate($headers['www-authenticate']);

        $future = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->add(new \DateInterval('PT10S'));
        $this->assertTrue($challenge->isExpired($future), 'challenge must be expired 10s past a 1s TTL');
    }

    public function testExpiresInZeroIsNeverExpiresOptOut(): void
    {
        // expiresIn = 0 is the documented dev-only opt-out: the challenge
        // is issued with no expires and never expires.
        $cfg = $this->makeConfigWithExpiresIn(0);
        $adapter = new Adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');

        $headers = $adapter->challengeHeaders($gate, $req);
        $challenge = \PayKit\Protocols\Mpp\Core\Headers::parseWwwAuthenticate($headers['www-authenticate']);

        $this->assertSame('', $challenge->expires, 'expiresIn=0 must issue an empty (never-expires) challenge');
        $farFuture = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->add(new \DateInterval('P3650D'));
        $this->assertFalse($challenge->isExpired($farFuture));
    }
}
