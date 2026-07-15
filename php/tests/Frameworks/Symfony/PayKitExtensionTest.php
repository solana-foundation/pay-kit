<?php

declare(strict_types=1);

namespace PayKit\Tests\Frameworks\Symfony;

use PayKit\Frameworks\Symfony\DependencyInjection\PayKitExtension;
use PayKit\Frameworks\Symfony\EventListener\RequirePaymentListener;
use PayKit\Protocols\Mpp\Adapter;
use PayKit\Store\ReplayStoreCapability;
use PayKit\Store\Store;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Argument\ServiceClosureArgument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

final class SymfonySharedReplayStore implements Store, ReplayStoreCapability
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

final class PayKitExtensionTest extends TestCase
{
    public function testProductionMppBootWiresConfiguredReplayStoreService(): void
    {
        $container = new ContainerBuilder();
        $container->register('app.mpp_replay_store', SymfonySharedReplayStore::class)->setPublic(true);
        $container->register('paykit.psr_http_factory', \stdClass::class)->setPublic(true);
        $container->register('paykit.http_foundation_factory', \stdClass::class)->setPublic(true);
        (new PayKitExtension())->load([[
            'network' => 'solana_devnet',
            'accept' => ['mpp'],
            'mpp_challenge_binding_secret' => 'test-secret-0123456789abcdef-0123456789',
            'mpp_replay_store_service' => 'app.mpp_replay_store',
            'preflight' => false,
        ]], $container);

        $store = $container->getDefinition(Adapter::class)->getArgument('$replayStore');
        self::assertInstanceOf(Reference::class, $store);
        self::assertSame('app.mpp_replay_store', (string) $store);
        $mppFactory = $container->getDefinition(RequirePaymentListener::class)->getArgument('$mppFactory');
        self::assertInstanceOf(ServiceClosureArgument::class, $mppFactory);
        self::assertInstanceOf(Reference::class, $mppFactory->getValues()[0]);
        self::assertSame(Adapter::class, (string) $mppFactory->getValues()[0]);
        self::assertNull($container->getDefinition(RequirePaymentListener::class)->getArgument('$mpp'));
        $container->compile();
        self::assertInstanceOf(Adapter::class, $container->get(Adapter::class));
    }

    public function testListenerRetainsLegacyAdapterArgumentBeforeLazyFactory(): void
    {
        $parameters = (new \ReflectionMethod(RequirePaymentListener::class, '__construct'))->getParameters();

        self::assertSame('mpp', $parameters[4]->getName());
        self::assertTrue($parameters[4]->allowsNull());
        self::assertInstanceOf(\ReflectionNamedType::class, $parameters[4]->getType());
        self::assertSame(Adapter::class, $parameters[4]->getType()->getName());

        self::assertSame('mppFactory', $parameters[5]->getName());
        self::assertTrue($parameters[5]->allowsNull());
        self::assertInstanceOf(\ReflectionNamedType::class, $parameters[5]->getType());
        self::assertSame('Closure', $parameters[5]->getType()->getName());
    }

    public function testX402OnlyBootDoesNotRegisterMppAdapter(): void
    {
        $container = new ContainerBuilder();
        (new PayKitExtension())->load([[
            'network' => 'solana_devnet',
            'accept' => ['x402'],
            'preflight' => false,
        ]], $container);

        self::assertFalse($container->hasDefinition(Adapter::class));
    }
}
