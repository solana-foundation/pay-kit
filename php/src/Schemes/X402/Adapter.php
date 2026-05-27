<?php

declare(strict_types=1);

namespace PayKit\Schemes\X402;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\Payment;
use PayKit\Scheme;
use PayKit\Schemes\X402\Exact\Verifier;
use PayKit\Store\MemoryStore;
use PayKit\Store\Store;
use Psr\Http\Message\ServerRequestInterface;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Rpc\RpcClient;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use Throwable;

/**
 * x402 (exact scheme, Solana) adapter. Issues challenges, runs the
 * 11-rule structural verifier on submitted credentials, cosigns as
 * the facilitator, and broadcasts via the configured RPC.
 *
 * Delegated mode (`X402Config::$facilitatorUrl` set) is reserved in
 * the config schema but not yet wired; the adapter raises
 * "delegated mode not implemented" when a facilitator URL is set.
 * Self-hosted is the only x402 path that ships in v1.
 */
final class Adapter
{
    private const PAYMENT_SIGNATURE_HEADER = 'payment-signature';
    private const X402_VERSION             = 2;
    private const TOKEN_PROGRAM            = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    private const CAIP2_MAINNET            = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
    private const CAIP2_DEVNET             = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';

    public function __construct(
        private readonly Config $config,
        private readonly Store $replayStore = new MemoryStore(),
    ) {
        if ($config->x402->isDelegated()) {
            throw new InvalidProofException(
                'pay_kit: x402 delegated mode is not yet implemented; '
                . 'leave X402Config::$facilitatorUrl null for self-hosted',
            );
        }
    }

    /**
     * Build a single entry for the 402 accepts[] array.
     *
     * @return array<string,mixed>
     */
    public function acceptsEntry(Gate $gate, ServerRequestInterface $request): array
    {
        $coin = $gate->amount->primaryCoin()?->value ?? $this->config->stablecoins[0]->value;
        $payTo = $gate->payTo ?? $this->config->effectiveRecipient();
        $amount = (string) $gate->total()->amount->multipliedBy(1_000_000)->toInt();
        $signer = $this->config->effectiveX402Signer();
        return [
            'protocol'          => 'x402',
            'scheme'            => 'exact',
            'network'           => $this->caip2(),
            'asset'             => $coin,
            'amount'            => $amount,
            'maxAmountRequired' => $amount,
            'payTo'             => $payTo,
            'maxTimeoutSeconds' => 60,
            'extra' => [
                'feePayer'     => $signer?->pubkey() ?? '',
                'decimals'     => 6,
                'tokenProgram' => self::TOKEN_PROGRAM,
                'memo'         => $request->getUri()->getPath(),
            ],
        ];
    }

    /**
     * @return array<string,string>
     */
    public function challengeHeaders(Gate $gate, ServerRequestInterface $request): array
    {
        $challenge = [
            'x402Version' => self::X402_VERSION,
            'resource'    => ['type' => 'http', 'url' => $request->getUri()->getPath()],
            'accepts'     => [$this->acceptsEntry($gate, $request)],
        ];
        return [
            'payment-required' => base64_encode(json_encode($challenge, JSON_THROW_ON_ERROR)),
        ];
    }

    public function verifyAndSettle(Gate $gate, ServerRequestInterface $request): Payment
    {
        $signer = $this->config->effectiveX402Signer();
        if ($signer === null) {
            throw new InvalidProofException('pay_kit: x402 requires operator.signer');
        }
        $header = $request->getHeaderLine('Payment-Signature');
        if ($header === '') {
            $header = $request->getHeaderLine('PAYMENT-SIGNATURE');
        }
        if ($header === '') {
            throw new InvalidProofException('pay_kit: payment required');
        }

        // Decode credential.
        $decoded = base64_decode($header, true);
        if ($decoded === false) {
            throw new InvalidProofException('invalid_exact_svm_payload_signature_base64');
        }
        try {
            $envelope = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new InvalidProofException('invalid_exact_svm_payload_signature_json');
        }
        if (!is_array($envelope) || ($envelope['x402Version'] ?? null) !== self::X402_VERSION) {
            throw new InvalidProofException('unsupported_x402_version');
        }
        $accepted = $envelope['accepted'] ?? null;
        $payload  = $envelope['payload']  ?? null;
        if (!is_array($accepted) || !is_array($payload)) {
            throw new InvalidProofException('invalid_exact_svm_payload_envelope');
        }

        // Identity-key match (cross-SDK PR #138 alignment).
        $offer = $this->acceptsEntry($gate, $request);
        foreach (['scheme', 'network', 'asset', 'payTo'] as $key) {
            if (($accepted[$key] ?? null) !== ($offer[$key] ?? null)) {
                throw new InvalidProofException(
                    'pay_kit: charge_request_mismatch: '
                    . 'accepted payment requirement does not match server challenge',
                );
            }
        }
        $offerExtra    = $offer['extra']    ?? [];
        $acceptedExtra = $accepted['extra'] ?? [];
        foreach (['feePayer', 'tokenProgram', 'memo'] as $key) {
            if (array_key_exists($key, $offerExtra)
                && ($acceptedExtra[$key] ?? null) !== $offerExtra[$key]) {
                throw new InvalidProofException(
                    'pay_kit: charge_request_mismatch (extra.' . $key . ')',
                );
            }
        }

        $txBase64 = is_string($payload['transaction'] ?? null) ? $payload['transaction'] : '';
        if ($txBase64 === '') {
            throw new InvalidProofException('invalid_exact_svm_payload_missing_transaction');
        }

        // Verify structural shape (11 rules).
        Verifier::verify($txBase64, $offer, [$signer->pubkey()]);

        // Cosign as facilitator.
        $rawTx = base64_decode($txBase64, true);
        if ($rawTx === false) {
            throw new InvalidProofException('invalid_exact_svm_payload_base64');
        }
        try {
            $tx = VersionedTransaction::deserialize($rawTx);
        } catch (Throwable) {
            throw new InvalidProofException('invalid_exact_svm_payload_transaction_parse');
        }
        $kp = Keypair::fromSecretKey($signer->secretKey());
        $tx->addSignature($kp->getPublicKey(), $kp->sign($tx->message->serialize()));
        $cosigned = base64_encode($tx->serialize());

        // Broadcast.
        $rpc = new RpcClient($this->config->rpcUrl);
        try {
            $sig = $rpc->sendTransaction($cosigned, ['encoding' => 'base64', 'skipPreflight' => false]);
        } catch (Throwable $e) {
            throw new InvalidProofException(
                'pay_kit: invalid proof: broadcast failed: ' . $e->getMessage(),
            );
        }
        if (!is_string($sig) || $sig === '') {
            throw new InvalidProofException('pay_kit: empty broadcast result');
        }

        // Reserve in replay store.
        if (!$this->replayStore->putIfAbsent('x402-svm-exact:consumed:' . $sig, true)) {
            throw new InvalidProofException('pay_kit: signature_consumed');
        }

        $responseEnvelope = base64_encode(json_encode([
            'success'     => true,
            'transaction' => $sig,
            'network'     => $accepted['network'] ?? $this->caip2(),
            'payer'       => $payload['transactionHash'] ?? '',
        ], JSON_THROW_ON_ERROR));

        return new Payment(
            scheme: Scheme::X402,
            transaction: $sig,
            gateName: null,
            settlementHeaders: [
                'payment-response'                => $responseEnvelope,
                'x-payment-settlement-signature'  => $sig,
            ],
            raw: $header,
        );
    }

    private function caip2(): string
    {
        return match ($this->config->network->value) {
            'solana_mainnet' => self::CAIP2_MAINNET,
            default          => self::CAIP2_DEVNET,
        };
    }
}
