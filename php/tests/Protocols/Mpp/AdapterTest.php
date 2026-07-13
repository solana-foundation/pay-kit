<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\Mpp;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\Config;
use PayKit\Exception\ConfigurationException;
use PayKit\PayCore\Currency;
use PayKit\Gate;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\Adapter;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Signer;
use PayKit\PayCore\Stablecoin;
use PayKit\Store\DurableStore;
use PayKit\Store\MemoryStore;
use PayKit\Store\ReplayStoreCapability;
use PayKit\Store\Store;
use PHPUnit\Framework\TestCase;

final class SharedAdapterReplayStore implements Store, ReplayStoreCapability
{
    /** @var array<string, mixed> */
    private array $values = [];

    public function putIfAbsent(string $key, mixed $value): bool
    {
        if (array_key_exists($key, $this->values)) {
            return false;
        }
        $this->values[$key] = $value;
        return true;
    }

    public function providesDurableSharedReplayProtection(): bool
    {
        return true;
    }
}

final class AdapterTest extends TestCase
{
    private function makeConfig(Network $network = Network::SolanaDevnet): Config
    {
        return new Config(
            network: $network,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer:    Signer::generate(),
                feePayer:  true,
            ),
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                replayStore: new AdapterDurableSharedReplayStore(),
            ),
        );
    }

    public function testNonLocalnetRejectsMissingReplayStore(): void
    {
        $config = new Config(
            network: Network::SolanaDevnet,
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01'),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('atomic durable/shared replay store');

        new Adapter($config);
    }

    public function testMainnetRejectsUnsafeMemoryStoreOverride(): void
    {
        $config = new Config(
            network: Network::SolanaMainnet,
            operator: new Operator(signer: Signer::generate()),
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                allowUnsafeMemoryStore: true,
            ),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('forbidden on mainnet');
        new Adapter($config);
    }

    public function testNonLocalnetRejectsStoreWithoutDurableSharedCapability(): void
    {
        $config = new Config(
            network: Network::SolanaDevnet,
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                replayStore: new MemoryStore(),
            ),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('does not affirm durable/shared capability');

        new Adapter($config);
    }

    private function adapter(Config $config): Adapter
    {
        return new Adapter($config, new SharedAdapterReplayStore());
    }

    public function testNonLocalnetRequiresInjectedReplayStore(): void
    {
        $config = new Config(
            network: Network::SolanaDevnet,
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
            ),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('atomic durable/shared replay store');
        new Adapter($config);
    }

    public function testNonLocalnetRejectsMemoryStore(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('does not affirm durable/shared capability');
        new Adapter($this->makeConfig(), new MemoryStore());
    }

    public function testNonLocalnetAcceptsDurableStoreContract(): void
    {
        self::assertInstanceOf(
            Adapter::class,
            new Adapter($this->makeConfig(), new AdapterDurableStore()),
        );
    }

    public function testNonLocalnetRejectsDurableStoreThatDoesNotAffirmDurability(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('does not affirm durable/shared capability');
        new Adapter($this->makeConfig(), new AdapterDurableStore(false));
    }

    public function testNonLocalnetRejectsConflictingReplayStoreDeclarations(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('does not affirm durable/shared capability');
        new Adapter($this->makeConfig(), new AdapterConflictingReplayStore());
    }

    public function testLocalnetStillRequiresExplicitUnsafeOptIn(): void
    {
        $config = new Config(
            network: Network::SolanaLocalnet,
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
            ),
        );

        $this->expectException(ConfigurationException::class);
        new Adapter($config);
    }

    public function testExplicitUnsafeDevelopmentMemoryStoreIsAllowed(): void
    {
        $config = $this->makeConfig(Network::SolanaLocalnet);
        $config = new Config(
            network: $config->network,
            operator: $config->operator,
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                allowUnsafeMemoryStore: true,
            ),
        );
        $adapter = new Adapter($config);
        self::assertInstanceOf(Adapter::class, $adapter);
    }

    public function testUnsafeOptInDoesNotAuthorizeArbitraryCustomStore(): void
    {
        $config = new Config(
            network: Network::SolanaLocalnet,
            operator: new Operator(signer: Signer::generate()),
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                allowUnsafeMemoryStore: true,
            ),
        );

        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('does not affirm durable/shared capability');
        new Adapter($config, new AdapterDurableStore(false));
    }

    public function testNonLocalnetAllowsInjectedStore(): void
    {
        self::assertInstanceOf(Adapter::class, $this->adapter($this->makeConfig()));
    }

    public function testNonLocalnetUsesStoreFromMppConfig(): void
    {
        $config = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(signer: Signer::generate()),
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                replayStore: new SharedAdapterReplayStore(),
            ),
        );
        self::assertInstanceOf(Adapter::class, new Adapter($config));
    }

    public function testAcceptsEntryShape(): void
    {
        $cfg = $this->makeConfig();
        $adapter = $this->adapter($cfg);
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
        $adapter = $this->adapter($cfg);
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
        $adapter = $this->adapter($cfg);
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
        $adapter = $this->adapter($cfg);
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
        $adapter = $this->adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $headers = $adapter->challengeHeaders($gate, $req);
        $this->assertArrayHasKey('www-authenticate', $headers);
        $this->assertStringStartsWith('Payment ', $headers['www-authenticate']);
    }

    public function testVerifyAndSettleWithoutAuthorizationRaises(): void
    {
        $cfg = $this->makeConfig();
        $adapter = $this->adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');
        $this->expectException(\PayKit\Exception\InvalidProofException::class);
        $adapter->verifyAndSettle($gate, $req);
    }

    /**
     * audit #19 (parity): the in-SDK Adapter path must pin the route's
     * currency/recipient/network/decimals into the ChargeServer so the
     * field-match checks in validateChargeRequest fire unconditionally at
     * issuance — matching Rust `validate_charge_request`. Previously serverFor
     * built the ChargeServer without pins, leaving those checks dormant on the
     * real route. These tests reach the route's ChargeServer via serverFor and
     * prove an off-route request is now rejected at issuance.
     */
    private function serverFor(Adapter $adapter, Gate $gate): \PayKit\Protocols\Mpp\Server\ChargeServer
    {
        $method = new \ReflectionMethod($adapter, 'serverFor');
        [$charges, $_handler] = $method->invoke($adapter, $gate);
        return $charges;
    }

    public function testAdapterPathIssuesValidChallengeForOnRouteRequest(): void
    {
        $cfg = $this->makeConfig();
        $adapter = $this->adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));

        // The on-route request built by the adapter must pass the (now-active)
        // pinned validation and produce a verifiable challenge.
        $charges = $this->serverFor($adapter, $gate);
        $chargeRequestMethod = new \ReflectionMethod($adapter, 'chargeRequestFor');
        $chargeRequest = $chargeRequestMethod->invoke($adapter, $gate);

        $challenge = $charges->createChallenge($chargeRequest);
        $this->assertTrue($challenge->verify($cfg->mpp->challengeBindingSecret ?? ''));
    }

    public function testAdapterPathRejectsMismatchedCurrencyAtIssuance(): void
    {
        $cfg = $this->makeConfig();
        $adapter = $this->adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $charges = $this->serverFor($adapter, $gate);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('currency does not match server configuration');
        $charges->createChallenge(new ChargeRequest(
            amount: '100000',
            currency: 'USDT',
            recipient: $cfg->effectiveRecipient(),
            methodDetails: ['network' => $cfg->network->mintsLabel()],
        ));
    }

    public function testAdapterPathRejectsMismatchedRecipientAtIssuance(): void
    {
        $cfg = $this->makeConfig();
        $adapter = $this->adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $charges = $this->serverFor($adapter, $gate);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('recipient does not match server configuration');
        $charges->createChallenge(new ChargeRequest(
            amount: '100000',
            currency: 'USDC',
            recipient: Signer::generate()->pubkey(),
            methodDetails: ['network' => $cfg->network->mintsLabel()],
        ));
    }

    public function testAdapterPathRejectsMismatchedNetworkAtIssuance(): void
    {
        $cfg = $this->makeConfig();
        $adapter = $this->adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $charges = $this->serverFor($adapter, $gate);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('network does not match server configuration');
        $charges->createChallenge(new ChargeRequest(
            amount: '100000',
            currency: 'USDC',
            recipient: $cfg->effectiveRecipient(),
            // config is SolanaDevnet -> "devnet"; advertise a different network.
            methodDetails: ['network' => 'mainnet'],
        ));
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
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                expiresIn: $expiresIn,
                replayStore: new AdapterDurableSharedReplayStore(),
            ),
        );
    }

    public function testChallengeWiresMppExpiresIntoIssuance(): void
    {
        // main-audit finding 7: config.mpp.expiresIn must thread into every
        // issued challenge as an RFC 3339 expires. Previously the adapter
        // issued challenges with no expiry, so they never expired.
        $cfg = $this->makeConfigWithExpiresIn(120);
        $adapter = $this->adapter($cfg);
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
        $adapter = $this->adapter($cfg);
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
        $adapter = $this->adapter($cfg);
        $gate = new Gate(amount: Price::usd('0.10'));
        $req = (new Psr17Factory())->createServerRequest('GET', '/paid');

        $headers = $adapter->challengeHeaders($gate, $req);
        $challenge = \PayKit\Protocols\Mpp\Core\Headers::parseWwwAuthenticate($headers['www-authenticate']);

        $this->assertSame('', $challenge->expires, 'expiresIn=0 must issue an empty (never-expires) challenge');
        $farFuture = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->add(new \DateInterval('P3650D'));
        $this->assertFalse($challenge->isExpired($farFuture));
    }
}

final class AdapterDurableSharedReplayStore implements Store, ReplayStoreCapability
{
    private MemoryStore $store;

    public function __construct()
    {
        $this->store = new MemoryStore();
    }

    public function putIfAbsent(string $key, mixed $value): bool
    {
        return $this->store->putIfAbsent($key, $value);
    }

    public function providesDurableSharedReplayProtection(): bool
    {
        return true;
    }
}

final class AdapterDurableStore implements DurableStore
{
    /** @var array<string, mixed> */
    private array $values = [];

    public function __construct(private bool $durable = true)
    {
    }

    public function putIfAbsent(string $key, mixed $value): bool
    {
        if (array_key_exists($key, $this->values)) {
            return false;
        }
        $this->values[$key] = $value;
        return true;
    }

    public function isDurable(): bool
    {
        return $this->durable;
    }
}

final class AdapterConflictingReplayStore implements DurableStore, ReplayStoreCapability
{
    public function putIfAbsent(string $key, mixed $value): bool
    {
        return true;
    }

    public function isDurable(): bool
    {
        return true;
    }

    public function providesDurableSharedReplayProtection(): bool
    {
        return false;
    }
}
