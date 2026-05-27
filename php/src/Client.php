<?php

declare(strict_types=1);

namespace PayKit;

/**
 * Immutable PayKit client. One instance per container; pass it to the
 * RequirePayment middleware, the framework adapters, and any code
 * that needs to introspect the resolved Config.
 *
 * `new Client($config)` runs the boot-time preflight (unless
 * `$config->preflight === false`) and raises if the operator wallet
 * is not ready. On `solana_localnet` + demo signer, missing fee-payer
 * SOL or recipient ATAs auto-bootstrap via Surfnet cheatcodes; see
 * {@see Preflight}.
 */
final readonly class Client
{
    public function __construct(public Config $config)
    {
        if ($config->preflight && !Preflight::isDisabledByEnv()) {
            Preflight::run($config);
        }

        if ($config->operator->signer?->isDemo() === true) {
            $logger = 'pay_kit: WARN: demo signer in use; never ship to production.';
            // Best-effort PSR-3 log; trigger_error fallback.
            if (function_exists('error_log')) {
                error_log($logger);
            }
        }
    }
}
