<?php

declare(strict_types=1);

namespace PayKit;

use PayKit\Exception\ConfigurationException;
use PayKit\Exception\DemoSignerOnMainnetException;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Protocols\X402\X402Config;
use PayKit\PayCore\Network;
use PayKit\PayCore\Stablecoin;

/**
 * Boot-time configuration. Immutable after construction.
 *
 * Validation runs in the constructor: invalid combinations
 * (demo signer on mainnet, empty stablecoins, etc.) raise
 * typed exceptions implementing {@see Exception\PayKitException}
 * so the host framework's boot pipeline catches them.
 */
final readonly class Config
{
    /** @var list<Protocol> */
    public array $accept;

    /** @var list<Stablecoin> */
    public array $stablecoins;

    public string $rpcUrl;

    public Operator $operator;

    public X402Config $x402;

    public MppConfig $mpp;

    /**
     * @param list<Protocol>      $accept       Ordered preference.
     * @param list<Stablecoin>  $stablecoins  Ordered settlement preference.
     */
    public function __construct(
        public Network $network = Network::SolanaLocalnet,
        array $accept = [Protocol::X402, Protocol::Mpp],
        array $stablecoins = [Stablecoin::Usdc],
        ?string $rpcUrl = null,
        ?Operator $operator = null,
        ?X402Config $x402 = null,
        ?MppConfig $mpp = null,
        public bool $preflight = true,
    ) {
        if ($accept === []) {
            throw new ConfigurationException('pay_kit: accept[] must not be empty');
        }
        foreach ($accept as $i => $a) {
            if (!$a instanceof Protocol) {
                throw new ConfigurationException(
                    sprintf('pay_kit: accept[%d] must be a Protocol enum', $i),
                );
            }
        }
        if ($stablecoins === []) {
            throw new ConfigurationException('pay_kit: stablecoins[] must not be empty');
        }
        foreach ($stablecoins as $i => $s) {
            if (!$s instanceof Stablecoin) {
                throw new ConfigurationException(
                    sprintf('pay_kit: stablecoins[%d] must be a Stablecoin enum', $i),
                );
            }
        }

        $resolvedOperator = ($operator ?? new Operator())->withDefaults();
        if (
            $this->network === Network::SolanaMainnet
            && $resolvedOperator->signer?->isDemo() === true
        ) {
            throw new DemoSignerOnMainnetException(
                'pay_kit: the package-shipped demo signer refuses to start on '
                . 'Network::SolanaMainnet. Load a real keypair via '
                . 'Signer::file() or Signer::env().',
            );
        }

        $this->accept      = array_values($accept);
        $this->stablecoins = array_values($stablecoins);
        $this->rpcUrl      = ($rpcUrl !== null && $rpcUrl !== '')
            ? $rpcUrl
            : $network->defaultRpcUrl();
        $this->operator    = $resolvedOperator;
        $this->x402        = $x402 ?? new X402Config();
        $resolvedMpp       = $mpp ?? new MppConfig();
        // Ruby PR #142 caveat #4: auto-resolve the MPP HMAC secret
        // when the caller didn't supply one (env -> ./.env -> generate
        // + persist). Mirrors ruby/lib/pay_kit/preflight.rb's
        // resolution chain so the demo apps boot zero-config. Skipped
        // when preflight is off (tests / read-only deploys) so the
        // suite doesn't leak .env files.
        if ($preflight
            && !\PayKit\Preflight::isDisabledByEnv()
            && ($resolvedMpp->challengeBindingSecret === null
                || $resolvedMpp->challengeBindingSecret === '')) {
            $resolved = \PayKit\Protocols\Mpp\SecretResolver::resolveMppSecret();
            $resolvedMpp = $resolvedMpp->withChallengeBindingSecret($resolved['secret']);
        }
        $this->mpp         = $resolvedMpp;
    }

    /**
     * The operator's recipient pubkey, post-defaults.
     */
    public function effectiveRecipient(): string
    {
        return $this->operator->effectiveRecipient();
    }

    /**
     * x402 facilitator signer override, defaulting to the operator's
     * signer.
     */
    public function effectiveX402Signer(): ?\PayKit\Signer\LocalSigner
    {
        return $this->x402->signer ?? $this->operator->signer;
    }

    public function withMpp(MppConfig $mpp): self
    {
        return new self(
            network:     $this->network,
            accept:      $this->accept,
            stablecoins: $this->stablecoins,
            rpcUrl:      $this->rpcUrl,
            operator:    $this->operator,
            x402:        $this->x402,
            mpp:         $mpp,
            preflight:   $this->preflight,
        );
    }
}
