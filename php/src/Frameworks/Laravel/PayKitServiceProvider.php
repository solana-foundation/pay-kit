<?php

declare(strict_types=1);

namespace PayKit\Frameworks\Laravel;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use PayKit\PayKit;
use PayKit\Config;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Pricing;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Protocols\X402\X402Config;
use PayKit\Signer;
use PayKit\PayCore\Stablecoin;

/**
 * Laravel service provider. Registers:
 *
 *   - `PayKit` as a singleton built from `config('paykit')`.
 *   - A route-middleware alias `paykit` pointing at
 *     {@see RequirePaymentMiddleware}.
 *
 * Apps publish the `config/paykit.php` shape DESIGN.md (#139) shows;
 * the provider dehydrates it into a {@see Config} instance and hands
 * it to the PayKit constructor.
 */
final class PayKitServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/config/paykit.php', 'paykit');

        $this->app->singleton(PayKit::class, function (Application $app): PayKit {
            /** @var array<string,mixed> $cfg */
            $cfg = $app['config']->get('paykit', []);
            return new PayKit(self::buildConfig($cfg));
        });
    }

    public function boot(Router $router): void
    {
        $this->publishes(
            [__DIR__ . '/config/paykit.php' => $this->app->configPath('paykit.php')],
            'paykit-config',
        );

        $router->aliasMiddleware('paykit', RequirePaymentMiddleware::class);
    }

    /**
     * @param array<string,mixed> $cfg
     */
    public static function buildConfig(array $cfg): Config
    {
        $network = self::network((string) ($cfg['network'] ?? 'solana_devnet'));
        $accept = self::acceptList($cfg['accept'] ?? ['x402', 'mpp']);
        $stablecoins = self::stablecoinList($cfg['stablecoins'] ?? ['USDC']);
        $rpcUrl = isset($cfg['rpc_url']) && $cfg['rpc_url'] !== '' ? (string) $cfg['rpc_url'] : null;
        $operatorCfg = $cfg['operator'] ?? [];
        $opRecipient = isset($operatorCfg['recipient']) && $operatorCfg['recipient'] !== ''
            ? (string) $operatorCfg['recipient'] : null;
        $opSigner = null;
        if (isset($operatorCfg['key']) && $operatorCfg['key'] !== '') {
            $opSigner = Signer::env('PAY_KIT_OPERATOR_KEY')
                ?? self::signerFromValue((string) $operatorCfg['key']);
        }
        $opFeePayer = (bool) ($operatorCfg['fee_payer'] ?? true);

        // A null/empty realm derives a per-recipient default (audit #15); a
        // shared literal like "Laravel" would put every Laravel app on one
        // credential namespace when they also share a binding secret.
        $rawRealm = $cfg['mpp']['realm'] ?? null;
        $mpp = new MppConfig(
            realm: ($rawRealm === null || (string) $rawRealm === '') ? null : (string) $rawRealm,
            challengeBindingSecret: isset($cfg['mpp_challenge_binding_secret'])
                && $cfg['mpp_challenge_binding_secret'] !== ''
                    ? (string) $cfg['mpp_challenge_binding_secret']
                    : null,
            expiresIn: MppConfig::resolveExpiresIn($cfg['mpp']['expires_in'] ?? null),
        );
        $x402 = new X402Config(
            facilitatorUrl: isset($cfg['x402_facilitator_url']) && $cfg['x402_facilitator_url'] !== ''
                ? (string) $cfg['x402_facilitator_url']
                : null,
        );

        return new Config(
            network: $network,
            accept: $accept,
            stablecoins: $stablecoins,
            rpcUrl: $rpcUrl,
            operator: new Operator($opRecipient, $opSigner, $opFeePayer),
            x402: $x402,
            mpp: $mpp,
            preflight: (bool) ($cfg['preflight'] ?? true),
        );
    }

    private static function network(string $s): Network
    {
        foreach (Network::cases() as $case) {
            if ($case->value === $s) {
                return $case;
            }
        }
        return Network::SolanaDevnet;
    }

    /**
     * @param array<int,string> $arr
     * @return list<Protocol>
     */
    private static function acceptList(array $arr): array
    {
        $out = [];
        foreach ($arr as $s) {
            foreach (Protocol::cases() as $case) {
                if ($case->value === $s) {
                    $out[] = $case;
                }
            }
        }
        return $out;
    }

    /**
     * @param array<int,string> $arr
     * @return list<Stablecoin>
     */
    private static function stablecoinList(array $arr): array
    {
        $out = [];
        foreach ($arr as $s) {
            foreach (Stablecoin::cases() as $case) {
                if ($case->value === $s) {
                    $out[] = $case;
                }
            }
        }
        return $out;
    }

    private static function signerFromValue(string $raw): ?\PayKit\Signer\LocalSigner
    {
        $trimmed = trim($raw);
        if ($trimmed === '') {
            return null;
        }
        if (str_starts_with($trimmed, '[')) {
            return Signer::json($trimmed);
        }
        if (strlen($trimmed) === 128 && ctype_xdigit($trimmed)) {
            return Signer::hex($trimmed);
        }
        return Signer::base58($trimmed);
    }
}
