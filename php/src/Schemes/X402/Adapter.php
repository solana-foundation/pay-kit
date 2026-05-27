<?php

declare(strict_types=1);

namespace PayKit\Schemes\X402;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\Payment;
use PayKit\Scheme;
use PayKit\Store\MemoryStore;
use PayKit\Store\Store;
use Psr\Http\Message\ServerRequestInterface;

/**
 * x402 (exact scheme on Solana) adapter. Stub: returns the canonical
 * 402 envelope and rejects credentials with InvalidProofException
 * until the 11-rule verifier ships (Phase 5).
 */
final class Adapter
{
    public function __construct(
        private readonly Config $config,
        private readonly Store $replayStore = new MemoryStore(),
    ) {
    }

    public function acceptsEntry(Gate $gate, ServerRequestInterface $request): array
    {
        $coin = $gate->amount->primaryCoin()?->value ?? $this->config->stablecoins[0]->value;
        $payTo = $gate->payTo ?? $this->config->effectiveRecipient();
        $amount = (string) $gate->total()->amount->multipliedBy(1_000_000)->toInt();
        return [
            'protocol'          => 'x402',
            'scheme'            => 'exact',
            'network'           => $this->caip2($this->config->network->value),
            'asset'             => $coin,
            'amount'            => $amount,
            'maxAmountRequired' => $amount,
            'payTo'             => $payTo,
            'maxTimeoutSeconds' => 60,
            'extra' => [
                'feePayer'     => $this->config->operator->signer?->pubkey() ?? '',
                'decimals'     => 6,
                'tokenProgram' => 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
                'memo'         => $request->getUri()->getPath(),
            ],
        ];
    }

    /**
     * @return array<string,string>
     */
    public function challengeHeaders(Gate $gate, ServerRequestInterface $request): array
    {
        $challenge = $this->acceptsEntry($gate, $request);
        return [
            'payment-required' => base64_encode((string) json_encode([
                'x402Version' => 2,
                'resource'    => ['type' => 'http', 'url' => $request->getUri()->getPath()],
                'accepts'     => [$challenge],
            ])),
        ];
    }

    public function verifyAndSettle(Gate $gate, ServerRequestInterface $request): Payment
    {
        throw new InvalidProofException('pay_kit: x402 verifier not yet implemented (Phase 5)');
    }

    private function caip2(string $network): string
    {
        return match ($network) {
            'solana_mainnet' => 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
            default          => 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
        };
    }
}
