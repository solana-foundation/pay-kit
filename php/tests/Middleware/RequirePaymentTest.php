<?php

declare(strict_types=1);

namespace PayKit\Tests\Middleware;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\PayKit;
use PayKit\Config;
use PayKit\Exception\ConfigurationException;
use PayKit\PayCore\Currency;
use PayKit\Gate;
use PayKit\Middleware\RequirePayment;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Payment;
use PayKit\Price;
use PayKit\Pricing;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Protocols\X402\Adapter as X402Adapter;
use PayKit\Signer;
use PayKit\Store\MemoryStore;
use PayKit\Store\ReplayStoreCapability;
use PayKit\Store\Store;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RequirePaymentTest extends TestCase
{
    private PayKit $client;
    private Psr17Factory $factory;

    public function testX402OnlyConstructionDoesNotRequireMppReplayStore(): void
    {
        $client = new PayKit(new Config(
            network: Network::SolanaDevnet,
            accept: [Protocol::X402],
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate()),
            preflight: false,
        ));
        $middleware = new RequirePayment($client, new Gate(amount: Price::usd('0.10')));
        self::assertInstanceOf(RequirePayment::class, $middleware);
    }

    public function testX402OnlyGateDoesNotConstructMppReplayStore(): void
    {
        $client = new PayKit(new Config(
            network: Network::SolanaDevnet,
            accept: [Protocol::X402, Protocol::Mpp],
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate()),
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
            ),
        ));
        $middleware = new RequirePayment(
            $client,
            new Gate(amount: Price::usd('0.10'), accept: [Protocol::X402]),
        );

        $response = $middleware->process(
            $this->factory->createServerRequest('GET', '/paid'),
            $this->nextHandler(),
        );

        self::assertSame(402, $response->getStatusCode());
    }

    protected function setUp(): void
    {
        $this->client = new PayKit(new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
            preflight: false,
            mpp: new MppConfig(
                challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01',
                replayStore: new MiddlewareDurableSharedReplayStore(),
            ),
        ));
        $this->factory = new Psr17Factory();
    }

    /**
     * @param Gate|string|\Closure(ServerRequestInterface):Gate $gateRef
     */
    private function middleware(Gate|string|\Closure $gateRef, ?Pricing $pricing = null): RequirePayment
    {
        return new RequirePayment(
            $this->client,
            $gateRef,
            $pricing,
            x402: new X402Adapter(
                $this->client->config,
                replayStore: new MiddlewareDurableSharedReplayStore(),
                recentBlockhashProvider: fn () => null,
            ),
        );
    }

    private function nextHandler(): RequestHandlerInterface
    {
        $factory = $this->factory;
        return new class ($factory) implements RequestHandlerInterface {
            public function __construct(private Psr17Factory $f)
            {
            }
            public function handle(ServerRequestInterface $req): ResponseInterface
            {
                return $this->f->createResponse(200)
                    ->withHeader('content-type', 'application/json')
                    ->withBody($this->f->createStream('{"ok":true}'));
            }
        };
    }

    public function testEmits402WhenNoCredentialPresent(): void
    {
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = $this->middleware($gate);
        $request = $this->factory->createServerRequest('GET', '/paid');
        $response = $mw->process($request, $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertIsArray($body);
        $this->assertSame('payment_required', $body['error']);
    }

    public function test402BodyCarriesAcceptsEntries(): void
    {
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = $this->middleware($gate);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertGreaterThanOrEqual(1, count($body['accepts']));
    }

    public function test402SetsCacheControlNoStore(): void
    {
        // main-audit medium finding 6: the umbrella 402 MUST NOT be
        // cached. Without no-store a CDN could replay a stale challenge
        // (different blockhash / expiry / amount) to a later client.
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = $this->middleware($gate);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
        $this->assertSame('no-store', $response->getHeaderLine('cache-control'));
    }

    public function testWwwAuthenticateHeaderStampedFromMpp(): void
    {
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = $this->middleware($gate);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $this->assertNotEmpty($response->getHeaderLine('www-authenticate'));
    }

    public function testStringHandleResolvedAgainstPricing(): void
    {
        $pricing = new class () extends Pricing {
            public readonly Gate $reportGate;
            public function __construct()
            {
                $this->reportGate = new Gate(amount: Price::usd('0.10'));
            }
        };
        $mw = $this->middleware('reportGate', $pricing);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
    }

    public function testClosureGateInvoked(): void
    {
        $closure = fn (ServerRequestInterface $req): Gate => new Gate(amount: Price::usd('0.25'));
        $mw = $this->middleware($closure);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
    }

    public function testStringHandleWithoutPricingRaises(): void
    {
        $mw = $this->middleware('reportGate');
        $this->expectException(\LogicException::class);
        $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
    }

    public function testMalformedAuthorizationFallsThroughTo402(): void
    {
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = $this->middleware($gate);
        $request = $this->factory->createServerRequest('GET', '/paid')
            ->withHeader('Authorization', 'Payment garbage-not-valid');
        $response = $mw->process($request, $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
    }

    public function testHeaderFilterNamespaceFunctions(): void
    {
        $request = $this->factory->createServerRequest('GET', '/');
        $this->assertNull(\PayKit\Middleware\payment($request));
        $this->assertFalse(\PayKit\Middleware\isPaid($request));

        $payment = new Payment(
            protocol: Protocol::Mpp,
            transaction: 'sig-123',
            gateName: 'report',
            settlementHeaders: [],
        );
        $request = $request->withAttribute('paykit.payment', $payment);
        $this->assertSame($payment, \PayKit\Middleware\payment($request));
        $this->assertTrue(\PayKit\Middleware\isPaid($request));
        $this->assertTrue(\PayKit\Middleware\isPaidFor($request, 'report'));
        $this->assertFalse(\PayKit\Middleware\isPaidFor($request, 'other'));

        // isPaidFor also accepts a Gate object: any settled payment satisfies it.
        $gate = new Gate(Price::usd('0.01'), 'PAY_TO_RECIPIENT_BASE58_PUBKEY_111111111111');
        $this->assertTrue(\PayKit\Middleware\isPaidFor($request, $gate));
    }

    public function testRequirePaymentNamespaceFunctionRaisesWithoutPayment(): void
    {
        $request = $this->factory->createServerRequest('GET', '/');
        $this->expectException(\PayKit\Exception\PaymentRequiredException::class);
        \PayKit\Middleware\requirePayment($request);
    }

    public function testMissingX402ReplayAdapterFailsClosedOnDevnet(): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('shared replay store is required outside localnet');

        new RequirePayment($this->client, new Gate(amount: Price::usd('0.10')));
    }
}

final class MiddlewareDurableSharedReplayStore implements Store, ReplayStoreCapability
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
