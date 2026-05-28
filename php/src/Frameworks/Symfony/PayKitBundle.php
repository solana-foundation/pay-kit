<?php

declare(strict_types=1);

namespace PayKit\Frameworks\Symfony;

use PayKit\Frameworks\Symfony\DependencyInjection\PayKitExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Symfony bundle. Mirrors `PayKit\\Laravel\\PayKitServiceProvider`.
 * Register in `config/bundles.php`:
 *
 *   return [\PayKit\Frameworks\Symfony\PayKitBundle::class => ['all' => true]];
 *
 * Then publish `config/packages/paykit.yaml`:
 *
 *   paykit:
 *       network: solana_devnet
 *       rpc_url: '%env(PAY_KIT_RPC_URL)%'
 *       operator:
 *           recipient: '%env(PAY_KIT_OPERATOR_RECIPIENT)%'
 *           key:       '%env(PAY_KIT_OPERATOR_KEY)%'
 *           fee_payer: true
 *       mpp_challenge_binding_secret: '%env(PAY_KIT_MPP_CHALLENGE_BINDING_SECRET)%'
 *
 * Controller actions gate via the
 * {@see \PayKit\Frameworks\Symfony\Attribute\RequirePayment} attribute.
 */
final class PayKitBundle extends Bundle
{
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new PayKitExtension();
    }
}
