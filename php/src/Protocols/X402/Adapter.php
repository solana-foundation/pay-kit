<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\Payment;
use PayKit\Protocol;
use PayKit\Protocols\X402\Exact\Verifier;
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

    /** @var \Closure():?string|null */
    private $recentBlockhashProvider = null;

    public function __construct(
        private readonly Config $config,
        private readonly Store $replayStore = new MemoryStore(),
        ?\Closure $recentBlockhashProvider = null,
    ) {
        if ($config->x402->isDelegated()) {
            throw new InvalidProofException(
                'pay_kit: x402 delegated mode is not yet implemented; '
                . 'leave X402Config::$facilitatorUrl null for self-hosted',
            );
        }
        $this->recentBlockhashProvider = $recentBlockhashProvider;
    }

    /**
     * Build a single entry for the 402 accepts[] array.
     *
     * @return array<string,mixed>
     */
    public function acceptsEntry(Gate $gate, ServerRequestInterface $request): array
    {
        $coin = $gate->amount->primaryCoin()?->value ?? $this->config->stablecoins[0]->value;
        // x402 spec puts the on-chain mint pubkey on `asset`, not the
        // ticker. Resolve the ticker to a mint via the legacy Mints
        // registry; Mints::resolve already falls back to the mainnet
        // row when the network row is absent (Ruby PR #142 caveat #1).
        $asset = \PayKit\PayCore\Solana\Mints::resolve($coin, $this->config->network->mintsLabel()) ?? $coin;
        $tokenProgram = \PayKit\PayCore\Solana\Mints::tokenProgramFor($coin, $this->config->network->mintsLabel());
        $payTo = $gate->payTo ?? $this->config->effectiveRecipient();
        $amount = (string) $gate->total()->amount->multipliedBy(1_000_000)->toInt();
        $signer = $this->config->effectiveX402Signer();
        $extra = [
            'feePayer'     => $signer?->pubkey() ?? '',
            'decimals'     => 6,
            'tokenProgram' => $tokenProgram,
            'memo'         => $request->getUri()->getPath(),
        ];
        // Ruby PR #142 caveat #5: stamp the server's recent_blockhash
        // into accepted.extra so pay-kit clients sign against the
        // same chain state the server will broadcast to. Closes the
        // surfpool / forked-mainnet drift the Sinatra example hit.
        // Scope: pay-kit Rust client honours this field; canonical
        // TS / Go x402 clients ignore it and call getLatestBlockhash
        // against their own RPC. Harmless on real networks.
        $blockhash = $this->fetchRecentBlockhash();
        if ($blockhash !== null) {
            $extra['recentBlockhash'] = $blockhash;
        }
        return [
            'protocol'          => 'x402',
            'scheme'            => 'exact',
            'network'           => $this->caip2(),
            'asset'             => $asset,
            'amount'            => $amount,
            'maxAmountRequired' => $amount,
            'payTo'             => $payTo,
            'maxTimeoutSeconds' => 60,
            'extra'             => $extra,
        ];
    }

    private function fetchRecentBlockhash(): ?string
    {
        if ($this->recentBlockhashProvider !== null) {
            try {
                $value = ($this->recentBlockhashProvider)();
                return is_string($value) && $value !== '' ? $value : null;
            } catch (Throwable) {
                return null;
            }
        }
        if ($this->config->rpcUrl === '') {
            return null;
        }
        try {
            $rpc = new \SolanaPhpSdk\Rpc\RpcClient($this->config->rpcUrl);
            $result = $rpc->getLatestBlockhash();
            $value = is_array($result) && isset($result['blockhash']) ? (string) $result['blockhash'] : null;
            return $value !== '' ? $value : null;
        } catch (Throwable) {
            return null;
        }
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
        $tx->partialSign($kp);
        $cosignedWire = $tx->serialize(verifySignatures: false);

        // Broadcast via the raw-wire path so PHP doesn't have to
        // reconstruct a SignedTransaction wrapper just to send.
        $rpc = new RpcClient($this->config->rpcUrl);
        try {
            $sig = $rpc->sendRawTransaction($cosignedWire, ['encoding' => 'base64', 'skipPreflight' => false]);
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
            protocol: Protocol::X402,
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
        return $this->config->network->caip2();
    }
}
