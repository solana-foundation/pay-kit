<?php

declare(strict_types=1);

namespace PayKit\Frameworks\Symfony\DependencyInjection;

use PayKit\Client;
use PayKit\Config;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Protocols\X402\X402Config;
use PayKit\Signer;
use PayKit\PayCore\Stablecoin;
use PayKit\Frameworks\Symfony\EventListener\RequirePaymentListener;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Wires {@see Client} into the Symfony service container from a
 * `paykit:` config section, and registers the kernel.controller_arguments
 * event listener that handles the {@see \PayKit\Frameworks\Symfony\Attribute\RequirePayment}
 * attribute.
 */
final class PayKitExtension extends Extension implements ConfigurationInterface
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $config = $this->processConfiguration($this, $configs);
        $payKitConfig = self::buildConfig($config);

        $client = new Client($payKitConfig);
        $container->set(Client::class, $client);

        $listener = $container->register(RequirePaymentListener::class)
            ->setArgument('$client', new Reference(Client::class))
            ->setArgument('$pricing', null)
            ->setArgument('$psrFactory', new Reference('paykit.psr_http_factory'))
            ->setArgument('$httpFactory', new Reference('paykit.http_foundation_factory'))
            ->setAutowired(true)
            ->setPublic(true);
        $listener->addTag('kernel.event_listener', [
            'event'  => 'kernel.controller_arguments',
            'method' => 'onKernelControllerArguments',
        ]);
    }

    public function getAlias(): string
    {
        return 'paykit';
    }

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $tree = new TreeBuilder('paykit');
        $root = $tree->getRootNode();
        $root->children()
            ->scalarNode('network')->defaultValue('solana_devnet')->end()
            ->scalarNode('rpc_url')->defaultNull()->end()
            ->arrayNode('accept')
                ->scalarPrototype()->end()
                ->defaultValue(['x402', 'mpp'])
            ->end()
            ->arrayNode('stablecoins')
                ->scalarPrototype()->end()
                ->defaultValue(['USDC'])
            ->end()
            ->arrayNode('operator')
                ->children()
                    ->scalarNode('recipient')->defaultNull()->end()
                    ->scalarNode('key')->defaultNull()->end()
                    ->booleanNode('fee_payer')->defaultTrue()->end()
                ->end()
            ->end()
            ->scalarNode('x402_facilitator_url')->defaultNull()->end()
            ->scalarNode('mpp_challenge_binding_secret')->defaultNull()->end()
            ->booleanNode('preflight')->defaultTrue()->end()
        ->end();
        return $tree;
    }

    /**
     * @param array<string,mixed> $cfg
     */
    public static function buildConfig(array $cfg): Config
    {
        $network = self::enumFromValue(Network::cases(), (string) ($cfg['network'] ?? 'solana_devnet'), Network::SolanaDevnet);
        $accept = [];
        foreach (($cfg['accept'] ?? []) as $s) {
            $case = self::enumFromValue(Protocol::cases(), (string) $s, null);
            if ($case !== null) {
                $accept[] = $case;
            }
        }
        $stablecoins = [];
        foreach (($cfg['stablecoins'] ?? []) as $s) {
            $case = self::enumFromValue(Stablecoin::cases(), (string) $s, null);
            if ($case !== null) {
                $stablecoins[] = $case;
            }
        }
        $opCfg = $cfg['operator'] ?? [];
        $signer = null;
        if (!empty($opCfg['key'])) {
            $raw = (string) $opCfg['key'];
            $trimmed = trim($raw);
            if (str_starts_with($trimmed, '[')) {
                $signer = Signer::json($trimmed);
            } elseif (strlen($trimmed) === 128 && ctype_xdigit($trimmed)) {
                $signer = Signer::hex($trimmed);
            } else {
                $signer = Signer::base58($trimmed);
            }
        }
        return new Config(
            network:     $network,
            accept:      $accept ?: [Protocol::X402, Protocol::Mpp],
            stablecoins: $stablecoins ?: [Stablecoin::Usdc],
            rpcUrl:      isset($cfg['rpc_url']) && $cfg['rpc_url'] !== '' ? (string) $cfg['rpc_url'] : null,
            operator:    new Operator(
                recipient: isset($opCfg['recipient']) && $opCfg['recipient'] !== '' ? (string) $opCfg['recipient'] : null,
                signer:    $signer,
                feePayer:  (bool) ($opCfg['fee_payer'] ?? true),
            ),
            x402: new X402Config(
                facilitatorUrl: isset($cfg['x402_facilitator_url']) && $cfg['x402_facilitator_url'] !== ''
                    ? (string) $cfg['x402_facilitator_url']
                    : null,
            ),
            mpp: new MppConfig(
                challengeBindingSecret: isset($cfg['mpp_challenge_binding_secret']) && $cfg['mpp_challenge_binding_secret'] !== ''
                    ? (string) $cfg['mpp_challenge_binding_secret']
                    : null,
            ),
            preflight: (bool) ($cfg['preflight'] ?? true),
        );
    }

    /**
     * @template T of \UnitEnum
     * @param list<T> $cases
     * @param T|null  $default
     * @return T|null
     */
    private static function enumFromValue(array $cases, string $value, ?object $default): ?object
    {
        foreach ($cases as $case) {
            if (property_exists($case, 'value') && $case->value === $value) {
                return $case;
            }
        }
        return $default;
    }
}
