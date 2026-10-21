<?php

declare(strict_types=1);

namespace PayKit\Tests\Middleware;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\PayKit;
use PayKit\Config;
use PayKit\Exception\SettlementInProgressException;
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
use PayKit\Signer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RequirePaymentTest extends TestCase
{
    private PayKit $client;
    private Psr17Factory $factory;

    protected function setUp(): void
    {
        $this->client = new PayKit(new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01'),
        ));
        $this->factory = new Psr17Factory();
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

    // The default MPP and x402 adapters claim payments in one store, so a
    // signature settled through either protocol is consumed for both.
    public function testDefaultAdaptersShareOneReplayStore(): void
    {
        $client = new PayKit(new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(recipient: Signer::generate()->pubkey(), signer: Signer::generate(), feePayer: true),
            preflight: false,
            accept: [Protocol::Mpp, Protocol::X402],
            mpp: new MppConfig(challengeBindingSecret: 'unit-test-secret-0123456789abcdef-01'),
        ));
        $mw = new RequirePayment($client, new Gate(amount: Price::usd('0.01')));
        $store = function (object $owner, string $property): object {
            $adapter = (new \ReflectionProperty($owner, $property))->getValue($owner);
            self::assertIsObject($adapter);
            $class = new \ReflectionClass($adapter);
            $field = $class->hasProperty('replayStore') ? 'replayStore' : 'consumedSignatures';
            $value = $class->getProperty($field)->getValue($adapter);
            self::assertIsObject($value);
            return $value;
        };
        $mppStore = $store($mw, 'mpp');
        $x402Ledger = $store($mw, 'x402');
        $x402Store = (new \ReflectionProperty($x402Ledger, 'store'))->getValue($x402Ledger);
        self::assertSame($mppStore, $x402Store);
    }

    // A payment that may already be on chain is answered with a retryable
    // 409, never a fresh challenge the client could pay a second time.
    public function testSettlementInProgressIsAnsweredWith409WithoutAChallenge(): void
    {
        $mw = new RequirePayment($this->client, new Gate(amount: Price::usd('0.01')));
        $build = new \ReflectionMethod($mw, 'build409');
        $response = $build->invoke($mw, new SettlementInProgressException('pay_kit: retry the same credential'));
        self::assertInstanceOf(ResponseInterface::class, $response);
        self::assertSame(409, $response->getStatusCode());
        self::assertSame('1', $response->getHeaderLine('retry-after'));
        self::assertSame('', $response->getHeaderLine('www-authenticate'));
        self::assertStringContainsString('settlement-in-progress', (string) $response->getBody());
    }

    public function testEmits402WhenNoCredentialPresent(): void
    {
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = new RequirePayment($this->client, $gate);
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
        $mw = new RequirePayment($this->client, $gate);
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
        $mw = new RequirePayment($this->client, $gate);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
        $this->assertSame('no-store', $response->getHeaderLine('cache-control'));
    }

    public function testWwwAuthenticateHeaderStampedFromMpp(): void
    {
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = new RequirePayment($this->client, $gate);
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
        $mw = new RequirePayment($this->client, 'reportGate', $pricing);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
    }

    public function testClosureGateInvoked(): void
    {
        $closure = fn (ServerRequestInterface $req): Gate => new Gate(amount: Price::usd('0.25'));
        $mw = new RequirePayment($this->client, $closure);
        $response = $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
        $this->assertSame(402, $response->getStatusCode());
    }

    public function testStringHandleWithoutPricingRaises(): void
    {
        $mw = new RequirePayment($this->client, 'reportGate');
        $this->expectException(\LogicException::class);
        $mw->process($this->factory->createServerRequest('GET', '/paid'), $this->nextHandler());
    }

    public function testMalformedAuthorizationFallsThroughTo402(): void
    {
        $gate = new Gate(amount: Price::usd('0.10'));
        $mw = new RequirePayment($this->client, $gate);
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
}
