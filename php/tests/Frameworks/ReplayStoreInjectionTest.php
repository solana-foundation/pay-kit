<?php

declare(strict_types=1);

namespace Symfony\Bridge\PsrHttpMessage\Factory {
    if (!class_exists(PsrHttpFactory::class)) {
        final class PsrHttpFactory
        {
            /** @var list<mixed> */
            private array $factories;

            public function __construct(mixed ...$factories)
            {
                $this->factories = $factories;
            }

            public function createRequest(mixed $request): \Psr\Http\Message\ServerRequestInterface
            {
                $method = method_exists($request, 'getMethod') ? $request->getMethod() : 'GET';
                $uri = method_exists($request, 'getRequestUri') ? $request->getRequestUri() : '/paid';

                return (new \Nyholm\Psr7\Factory\Psr17Factory())->createServerRequest($method, $uri);
            }
        }
    }

    if (!class_exists(HttpFoundationFactory::class)) {
        final class HttpFoundationFactory
        {
            public function createResponse(\Psr\Http\Message\ResponseInterface $response): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response(
                    (string) $response->getBody(),
                    $response->getStatusCode(),
                    $response->getHeaders(),
                );
            }
        }
    }
}

namespace Illuminate\Contracts\Container {
    if (!interface_exists(Container::class)) {
        interface Container
        {
            public function bound(string $abstract): bool;

            public function make(string $abstract): mixed;
        }
    }
}

namespace Illuminate\Contracts\Foundation {
    if (!interface_exists(Application::class)) {
        interface Application extends \Illuminate\Contracts\Container\Container, \ArrayAccess
        {
            public function singleton(string $abstract, \Closure $concrete): void;

            public function bind(string $abstract, \Closure $concrete): void;

            public function configPath(string $path = ''): string;
        }
    }
}

namespace Illuminate\Support {
    if (!class_exists(ServiceProvider::class)) {
        abstract class ServiceProvider
        {
            public function __construct(protected \Illuminate\Contracts\Foundation\Application $app)
            {
            }

            protected function mergeConfigFrom(string $path, string $key): void
            {
            }

            /** @param array<string,string> $paths */
            protected function publishes(array $paths, ?string $group = null): void
            {
            }
        }
    }
}

namespace Illuminate\Routing {
    if (!class_exists(Router::class)) {
        final class Router
        {
            /** @var array<string,class-string> */
            private array $aliases = [];

            /** @param class-string $class */
            public function aliasMiddleware(string $name, string $class): void
            {
                $this->aliases[$name] = $class;
            }

            public function middlewareAlias(string $name): ?string
            {
                return $this->aliases[$name] ?? null;
            }
        }
    }
}

namespace Illuminate\Http {
    if (!class_exists(Request::class)) {
        final class Request
        {
            public object $attributes;

            public function __construct()
            {
                $this->attributes = new class () {
                    /** @var array<string,mixed> */
                    private array $values = [];

                    public function get(string $key): mixed
                    {
                        return $this->values[$key] ?? null;
                    }

                    public function set(string $key, mixed $value): void
                    {
                        $this->values[$key] = $value;
                    }
                };
            }
        }
    }
}

namespace PayKit\Tests\Frameworks {
    use Illuminate\Contracts\Container\Container as LaravelContainerContract;
    use Illuminate\Contracts\Foundation\Application as LaravelApplicationContract;
    use Illuminate\Http\Request as LaravelRequest;
    use Illuminate\Routing\Router as LaravelRouter;
    use Nyholm\Psr7\Factory\Psr17Factory;
    use PayKit\Config;
    use PayKit\Exception\ConfigurationException;
    use PayKit\Frameworks\Laravel\PayKitServiceProvider;
    use PayKit\Frameworks\Laravel\RequirePaymentMiddleware;
    use PayKit\Frameworks\Symfony\Attribute\RequirePayment as SymfonyRequirePayment;
    use PayKit\Frameworks\Symfony\DependencyInjection\PayKitExtension;
    use PayKit\Frameworks\Symfony\EventListener\RequirePaymentListener;
    use PayKit\Gate;
    use PayKit\Operator;
    use PayKit\PayCore\Network;
    use PayKit\PayKit;
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
    use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
    use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
    use Symfony\Component\DependencyInjection\ContainerBuilder;
    use Symfony\Component\DependencyInjection\Reference;
    use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
    use Symfony\Component\HttpFoundation\Response;
    use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
    use Symfony\Component\HttpKernel\HttpKernelInterface;

    final class ReplayStoreInjectionTest extends TestCase
    {
        private PayKit $client;

        protected function setUp(): void
        {
            $signer = Signer::generate();
            $this->client = new PayKit(new Config(
                network: Network::SolanaDevnet,
                accept: [Protocol::X402],
                operator: new Operator(
                    recipient: $signer->pubkey(),
                    signer: $signer,
                    feePayer: true,
                ),
                mpp: new MppConfig(
                    challengeBindingSecret: 'framework-test-secret-0123456789abcdef',
                    replayStore: new FrameworkDurableSharedReplayStore(),
                ),
                preflight: false,
            ));
        }

        public function testLaravelUsesInjectedX402Adapter(): void
        {
            $middleware = new RequirePaymentMiddleware(
                $this->client,
                new FrameworkLaravelContainer($this->pricing()),
                $this->psrFactory(),
                new HttpFoundationFactory(),
                $this->x402Adapter(),
            );

            $response = $middleware->handle(
                new LaravelRequest(),
                static fn (): Response => new Response('next'),
                'paid',
            );

            self::assertSame(402, $response->getStatusCode());
        }

        public function testLaravelFailsClosedWithoutAnInjectedX402Adapter(): void
        {
            $middleware = new RequirePaymentMiddleware(
                $this->client,
                new FrameworkLaravelContainer($this->pricing()),
                $this->psrFactory(),
                new HttpFoundationFactory(),
            );

            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('shared replay store is required outside localnet');
            $middleware->handle(new LaravelRequest(), static fn (): Response => new Response('next'), 'paid');
        }

        public function testLaravelMppOnlyProviderBootsAndRunsWithoutX402State(): void
        {
            $app = $this->laravelApplication([
                'network' => 'solana_localnet',
                'accept' => ['mpp'],
                'preflight' => false,
                'mpp_challenge_binding_secret' => 'framework-test-secret-0123456789abcdef',
                'x402_replay_store' => 'missing.x402.replay_store',
            ]);
            $provider = new PayKitServiceProvider($app);

            $provider->register();
            $router = new LaravelRouter();
            $provider->boot($router);

            self::assertFalse($app->bound(X402Adapter::class));
            self::assertSame(RequirePaymentMiddleware::class, $router->middlewareAlias('paykit'));
            $middleware = $app->make(RequirePaymentMiddleware::class);
            self::assertInstanceOf(RequirePaymentMiddleware::class, $middleware);

            $response = $middleware->handle(
                new LaravelRequest(),
                static fn (): Response => new Response('next'),
                'paid',
            );
            self::assertSame(402, $response->getStatusCode());
            self::assertNotSame('', $response->headers->get('www-authenticate', ''));
        }

        public function testLaravelDefaultProtocolsStillRegisterX402Adapter(): void
        {
            $app = $this->laravelApplication([
                'network' => 'solana_localnet',
                'preflight' => false,
                'mpp_challenge_binding_secret' => 'framework-test-secret-0123456789abcdef',
            ]);

            (new PayKitServiceProvider($app))->register();

            self::assertTrue($app->bound(X402Adapter::class));
            self::assertInstanceOf(RequirePaymentMiddleware::class, $app->make(RequirePaymentMiddleware::class));
        }

        public function testSymfonyUsesInjectedX402Adapter(): void
        {
            $listener = new RequirePaymentListener(
                $this->client,
                $this->pricing(),
                $this->psrFactory(),
                new HttpFoundationFactory(),
                $this->x402Adapter(),
            );
            $event = $this->symfonyEvent();

            $listener->onKernelControllerArguments($event);

            $response = ($event->getController())();
            self::assertInstanceOf(Response::class, $response);
            self::assertSame(402, $response->getStatusCode());
        }

        public function testSymfonyFailsClosedWithoutAnInjectedX402Adapter(): void
        {
            $listener = new RequirePaymentListener(
                $this->client,
                $this->pricing(),
                $this->psrFactory(),
                new HttpFoundationFactory(),
            );

            $this->expectException(ConfigurationException::class);
            $this->expectExceptionMessage('shared replay store is required outside localnet');
            $listener->onKernelControllerArguments($this->symfonyEvent());
        }

        public function testSymfonyMppOnlyContainerBootsAndRunsWithoutX402State(): void
        {
            $container = new ContainerBuilder();
            $container->set('paykit.psr_http_factory', $this->psrFactory());
            $container->set('paykit.http_foundation_factory', new HttpFoundationFactory());

            (new PayKitExtension())->load([[
                'network' => 'solana_localnet',
                'accept' => ['mpp'],
                'preflight' => false,
                'mpp_challenge_binding_secret' => 'framework-test-secret-0123456789abcdef',
                'x402_replay_store' => 'missing.x402.replay_store',
            ]], $container);

            self::assertFalse($container->hasDefinition(X402Adapter::class));
            $listenerDefinition = $container->getDefinition(RequirePaymentListener::class);
            self::assertNull($listenerDefinition->getArgument('$x402'));
            $listenerDefinition->setArgument('$pricing', $this->pricing());

            $listener = $container->get(RequirePaymentListener::class);
            self::assertInstanceOf(RequirePaymentListener::class, $listener);
            $event = $this->symfonyEvent();
            $listener->onKernelControllerArguments($event);

            $response = ($event->getController())();
            self::assertInstanceOf(Response::class, $response);
            self::assertSame(402, $response->getStatusCode());
            self::assertNotSame('', $response->headers->get('www-authenticate', ''));
        }

        public function testSymfonyDefaultProtocolsInjectConfiguredReplayStoreIntoTheX402Adapter(): void
        {
            $container = new ContainerBuilder();
            $container->set('app.replay_store', new FrameworkDurableSharedReplayStore());
            $container->set('paykit.psr_http_factory', new \stdClass());
            $container->set('paykit.http_foundation_factory', new \stdClass());

            (new PayKitExtension())->load([[
                'network' => 'solana_devnet',
                'preflight' => false,
                'x402_replay_store' => 'app.replay_store',
            ]], $container);

            $adapter = $container->getDefinition(X402Adapter::class);
            $replayStore = $adapter->getArgument('$replayStore');
            self::assertInstanceOf(Reference::class, $replayStore);
            self::assertSame('app.replay_store', (string) $replayStore);

            $listener = $container->getDefinition(RequirePaymentListener::class);
            $listenerAdapter = $listener->getArgument('$x402');
            self::assertInstanceOf(Reference::class, $listenerAdapter);
            self::assertSame(X402Adapter::class, (string) $listenerAdapter);
            self::assertInstanceOf(X402Adapter::class, $container->get(X402Adapter::class));
        }

        private function pricing(): Pricing
        {
            return new class () extends Pricing {
                public readonly Gate $paid;

                public function __construct()
                {
                    $this->paid = new Gate(amount: Price::usd('0.10'));
                }
            };
        }

        private function x402Adapter(): X402Adapter
        {
            return new X402Adapter(
                $this->client->config,
                replayStore: new FrameworkDurableSharedReplayStore(),
                recentBlockhashProvider: fn () => null,
            );
        }

        /** @param array<string,mixed> $config */
        private function laravelApplication(array $config): FrameworkLaravelApplication
        {
            $app = new FrameworkLaravelApplication($config);
            $app->instance(Pricing::class, $this->pricing());
            $app->instance(PsrHttpFactory::class, $this->psrFactory());
            $app->instance(HttpFoundationFactory::class, new HttpFoundationFactory());

            return $app;
        }

        private function psrFactory(): PsrHttpFactory
        {
            $constructor = (new \ReflectionClass(PsrHttpFactory::class))->getConstructor();
            $arguments = array_fill(0, $constructor?->getNumberOfRequiredParameters() ?? 0, new Psr17Factory());

            return new PsrHttpFactory(...$arguments);
        }

        private function symfonyEvent(): ControllerArgumentsEvent
        {
            return new ControllerArgumentsEvent(
                new FrameworkKernel(),
                [new FrameworkPaidController(), 'paid'],
                [],
                SymfonyRequest::create('/paid'),
                HttpKernelInterface::MAIN_REQUEST,
            );
        }
    }

    final class FrameworkLaravelContainer implements LaravelContainerContract
    {
        public function __construct(private readonly Pricing $pricing)
        {
        }

        public function bound(string $abstract): bool
        {
            return $abstract === Pricing::class;
        }

        public function make(string $abstract): mixed
        {
            if ($abstract === Pricing::class) {
                return $this->pricing;
            }

            throw new \LogicException("Unexpected Laravel container resolution: $abstract");
        }
    }

    final class FrameworkLaravelApplication implements LaravelApplicationContract
    {
        /** @var array<string,object> */
        private array $instances = [];

        /** @var array<string,\Closure> */
        private array $singletons = [];

        /** @var array<string,\Closure> */
        private array $bindings = [];

        /** @param array<string,mixed> $config */
        public function __construct(array $config)
        {
            $this->instances['config'] = new FrameworkLaravelConfigRepository(['paykit' => $config]);
        }

        public function singleton(string $abstract, \Closure $concrete): void
        {
            $this->singletons[$abstract] = $concrete;
        }

        public function bind(string $abstract, \Closure $concrete): void
        {
            $this->bindings[$abstract] = $concrete;
        }

        public function configPath(string $path = ''): string
        {
            return '/tmp/' . ltrim($path, '/');
        }

        public function instance(string $abstract, object $instance): void
        {
            $this->instances[$abstract] = $instance;
        }

        public function bound(string $abstract): bool
        {
            return isset($this->instances[$abstract])
                || isset($this->singletons[$abstract])
                || isset($this->bindings[$abstract]);
        }

        public function make(string $abstract): mixed
        {
            if (isset($this->instances[$abstract])) {
                return $this->instances[$abstract];
            }
            if (isset($this->singletons[$abstract])) {
                $instance = ($this->singletons[$abstract])($this);
                if (!is_object($instance)) {
                    throw new \LogicException("Laravel singleton did not resolve an object: $abstract");
                }
                return $this->instances[$abstract] = $instance;
            }
            if (isset($this->bindings[$abstract])) {
                return ($this->bindings[$abstract])($this);
            }

            throw new \LogicException("Unexpected Laravel application resolution: $abstract");
        }

        public function offsetExists(mixed $offset): bool
        {
            return is_string($offset) && isset($this->instances[$offset]);
        }

        public function offsetGet(mixed $offset): mixed
        {
            return is_string($offset) ? $this->make($offset) : null;
        }

        public function offsetSet(mixed $offset, mixed $value): void
        {
            if (!is_string($offset) || !is_object($value)) {
                throw new \LogicException('Laravel application offsets require a string and object');
            }
            $this->instances[$offset] = $value;
        }

        public function offsetUnset(mixed $offset): void
        {
            if (is_string($offset)) {
                unset($this->instances[$offset]);
            }
        }
    }

    final class FrameworkLaravelConfigRepository
    {
        /** @param array<string,mixed> $values */
        public function __construct(private readonly array $values)
        {
        }

        public function get(string $key, mixed $default = null): mixed
        {
            $value = $this->values;
            foreach (explode('.', $key) as $segment) {
                if (!is_array($value) || !array_key_exists($segment, $value)) {
                    return $default;
                }
                $value = $value[$segment];
            }

            return $value;
        }
    }

    final class FrameworkKernel implements HttpKernelInterface
    {
        public function handle(SymfonyRequest $request, int $type = self::MAIN_REQUEST, bool $catch = true): Response
        {
            return new Response();
        }
    }

    final class FrameworkPaidController
    {
        #[SymfonyRequirePayment('paid')]
        public function paid(): Response
        {
            return new Response('paid');
        }
    }

    final class FrameworkDurableSharedReplayStore implements Store, ReplayStoreCapability
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
}
