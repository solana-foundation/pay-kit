<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\Payment;
use PayKit\Protocol;
use PayKit\PayCore\Rpc\RpcGateway;
use PayKit\PayCore\Rpc\SolanaRpcGateway;
use PayKit\Protocols\X402\Exact\PaymentExtensions;
use PayKit\Protocols\X402\Exact\Verifier;
use PayKit\Store\MemoryStore;
use PayKit\Store\Store;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
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
    // Legacy x402 client payment header (coinbase/x402 SVM). v1 carries the
    // credential here instead of PAYMENT-SIGNATURE; the server reads the v2
    // header first, then falls back to this one. Mirrors the rust spine
    // constants X402_V1_PAYMENT_HEADER / X402_V2_PAYMENT_HEADER.
    private const PAYMENT_LEGACY_HEADER    = 'x-payment';
    // x402 protocol versions. X402_VERSION is the version this server EMITS by
    // default (the canonical current wire); X402_VERSION_V1 is the legacy wire
    // this server still ACCEPTS on the dual-accept read path. Mirrors the rust
    // X402_VERSION_V1 / X402_VERSION_V2 constants.
    private const X402_VERSION             = 2;
    private const X402_VERSION_V1          = 1;
    private const TOKEN_PROGRAM            = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    private const EXACT_SCHEME             = 'exact';
    private const REPLAY_KEY_PREFIX        = 'x402-svm-exact:consumed:';

    // Canonical CAIP-2 chain identifiers (match Network::caip2() + the rust
    // spine types.rs). Used to normalize a legacy v1 plain network slug
    // ("solana", "solana-devnet", "solana-testnet") to the chain id the route
    // is pinned to, so the v1 network gate compares apples to apples.
    private const CAIP2_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
    private const CAIP2_DEVNET  = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
    private const CAIP2_TESTNET = 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z';

    /** @var \Closure():?string|null */
    private $recentBlockhashProvider = null;

    private ?RpcGateway $rpc = null;

    private readonly Store $replayStore;

    /**
     * @param ?Store $replayStore Replay-protection store. When null (the
     *        default) an in-process {@see MemoryStore} is used and a loud
     *        dev-only warning is emitted: a single-process memory store
     *        loses replay protection across workers/restarts, so production
     *        deployments MUST inject a shared atomic store (Redis, Postgres).
     * @param ?RpcGateway $rpc Confirmation/broadcast gateway. Defaults to a
     *        {@see SolanaRpcGateway} over the configured `rpcUrl`, created
     *        lazily on first settlement. Inject a fake for unit tests.
     * @param int $confirmationAttempts How many times to poll
     *        `getSignatureStatuses` before giving up. 40 attempts at the
     *        default delay = 10 seconds. Mirrors the MPP charge handler.
     * @param int $confirmationDelayMicros Sleep between polls in microseconds.
     */
    public function __construct(
        private readonly Config $config,
        ?Store $replayStore = null,
        ?\Closure $recentBlockhashProvider = null,
        ?RpcGateway $rpc = null,
        private readonly int $confirmationAttempts = 40,
        private readonly int $confirmationDelayMicros = 250_000,
    ) {
        if ($config->x402->isDelegated()) {
            throw new InvalidProofException(
                'pay_kit: x402 delegated mode is not yet implemented; '
                . 'leave X402Config::$facilitatorUrl null for self-hosted',
            );
        }
        if ($replayStore === null) {
            self::warnDefaultReplayStore();
            $replayStore = new MemoryStore();
        }
        $this->replayStore = $replayStore;
        $this->recentBlockhashProvider = $recentBlockhashProvider;
        $this->rpc = $rpc;
    }

    private static function warnDefaultReplayStore(): void
    {
        if (function_exists('error_log')) {
            error_log(
                'pay_kit: WARN: x402 adapter using in-memory replay store; '
                . 'dev-only. Inject a shared atomic Store (Redis/Postgres) in production.',
            );
        }
    }

    private function rpc(): RpcGateway
    {
        return $this->rpc ??= new SolanaRpcGateway(new RpcClient($this->config->rpcUrl));
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
        // Advertise the x402 v2 `extensions` object when the operator
        // configured one (e.g. a required payment-identifier). Omit the key
        // entirely when none is configured, never an empty `{}` (mirrors rust
        // `PaymentRequiredEnvelope.extensions` skip_serializing_if = Option::is_none).
        $extensions = $this->config->x402?->advertisedExtensions ?? null;
        if (is_array($extensions) && $extensions !== []) {
            $challenge['extensions'] = $extensions;
        }
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
        // Dual-accept read: the canonical (current) credential rides the
        // PAYMENT-SIGNATURE header; the legacy credential rides X-PAYMENT.
        // Read the canonical header first, then fall back to the legacy one,
        // mirroring the rust spine's read precedence. A server NEVER rejects a
        // well-formed legacy credential just because it arrived on X-PAYMENT.
        $header = $request->getHeaderLine('Payment-Signature');
        if ($header === '') {
            $header = $request->getHeaderLine('PAYMENT-SIGNATURE');
        }
        if ($header === '') {
            $header = $request->getHeaderLine('X-Payment');
        }
        if ($header === '') {
            $header = $request->getHeaderLine('X-PAYMENT');
        }
        if ($header === '') {
            throw new InvalidProofException('pay_kit: payment required');
        }

        $envelope = $this->decodeCredential($header);
        $offer    = $this->acceptsEntry($gate, $request);

        // Version dispatch. The canonical wire commits to a full `accepted`
        // requirement object (identity-key matched below); the legacy wire
        // commits only to a top-level scheme + plain network slug, which the
        // server normalizes and gates against its route. Adding legacy support
        // must NOT widen the version gate: a genuinely-unknown version is still
        // rejected. Mirrors rust parse_payment_signature (server/exact.rs).
        $version = $envelope['x402Version'] ?? null;
        if ($version === self::X402_VERSION) {
            $this->matchCanonicalCredential($envelope, $offer);
        } elseif ($version === self::X402_VERSION_V1) {
            $this->matchLegacyCredential($envelope);
        } else {
            throw new InvalidProofException('unsupported_x402_version');
        }

        $payload = $envelope['payload'] ?? null;
        if (!is_array($payload)) {
            throw new InvalidProofException('invalid_exact_svm_payload_envelope');
        }

        // x402 v2 extensions reject gate. When the server advertised a
        // payment-identifier with info.required = true, the credential MUST
        // echo back a valid `pay_`-shaped id (^[A-Za-z0-9_-]{16,128}$) or the
        // request is rejected (coinbase payment_identifier spec: HTTP 400).
        // Mirrors rust `requires_payment_identifier` + the reject-when-required
        // -and-missing check layered on verify_envelope_payload. The identity-
        // key match itself now lives in matchCanonicalCredential (run by the
        // version dispatch above); only the extensions gate is layered here.
        $advertised = PaymentExtensions::fromArray($this->config->x402?->advertisedExtensions ?? null);
        if ($advertised !== null && $advertised->requiresPaymentIdentifier()) {
            $echoed = PaymentExtensions::fromArray(
                is_array($envelope['extensions'] ?? null) ? $envelope['extensions'] : null,
            );
            $info = $echoed?->paymentIdentifier?->info;
            if ($info === null || $info->id === null || $info->id === '') {
                throw new InvalidProofException(
                    'pay_kit: payment-identifier required but credential echoed no id',
                );
            }
            if (!$info->hasValidId()) {
                throw new InvalidProofException(
                    'pay_kit: payment-identifier id is invalid: ' . $info->id
                    . ' does not match ^[A-Za-z0-9_-]{16,128}$',
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
        $rpc = $this->rpc();
        try {
            $sig = $rpc->sendRawTransaction($cosignedWire, [
                'encoding' => 'base64',
                'skipPreflight' => false,
                'preflightCommitment' => 'confirmed',
            ]);
        } catch (Throwable $e) {
            throw new InvalidProofException(
                'pay_kit: invalid proof: broadcast failed: ' . $e->getMessage(),
            );
        }
        if (!is_string($sig) || $sig === '') {
            throw new InvalidProofException('pay_kit: empty broadcast result');
        }

        // Reserve in the replay store BETWEEN broadcast and confirmation.
        // RPC has accepted the transaction, so it may land even if the
        // await below times out or the process crashes. Reserving first
        // means a retry of the same credential trips the consumed guard
        // rather than re-settling. Mirrors the MPP SolanaChargeHandler
        // (settle() reserves between sendRawTransaction and
        // awaitConfirmation; PR #85 Greptile P1 / audit gap G05).
        if (!$this->replayStore->putIfAbsent(self::REPLAY_KEY_PREFIX . $sig, true)) {
            throw new InvalidProofException('pay_kit: signature_consumed');
        }

        // Confirm BEFORE returning the payment-response success. RPC
        // acceptance is not settlement: the transaction can still fail or
        // never finalize. Poll getSignatureStatuses until confirmed or
        // finalized, throwing on on-chain failure or timeout so callers
        // never receive a success header for an unsettled transaction.
        // Closes main-audit finding 3 (PHP x402 confirm-before-success).
        try {
            $this->awaitConfirmation($sig);
        } catch (Throwable $e) {
            throw new InvalidProofException(
                'pay_kit: invalid proof: settlement not confirmed: ' . $e->getMessage(),
            );
        }

        // Echo the network the credential committed to in the settlement
        // response: the canonical wire's `accepted.network` (CAIP-2) or the
        // legacy wire's top-level plain network slug, falling back to the
        // route's CAIP-2 id. Mirrors the rust v1/v2 settlement-response shape.
        $responseEnvelope = base64_encode(json_encode([
            'success'     => true,
            'transaction' => $sig,
            'network'     => $this->settlementNetwork($envelope),
            'payer'       => $payload['transactionHash'] ?? '',
        ], JSON_THROW_ON_ERROR));

        // v1 credentials get the legacy X-PAYMENT-RESPONSE receipt header; v2
        // uses PAYMENT-RESPONSE (rust X402_V1_PAYMENT_RESPONSE_HEADER,
        // constants.rs:22; matches go/lua/ruby/swift).
        $responseHeader = ($version === self::X402_VERSION_V1) ? 'x-payment-response' : 'payment-response';

        return new Payment(
            protocol: Protocol::X402,
            transaction: $sig,
            gateName: null,
            settlementHeaders: [
                $responseHeader                   => $responseEnvelope,
                'x-payment-settlement-signature'  => $sig,
            ],
            raw: $header,
        );
    }

    /**
     * Poll `getSignatureStatuses` through the PayCore {@see RpcGateway}
     * until the broadcast transaction is confirmed or finalized. Throws on
     * on-chain failure (`err`) or when the confirmation budget is exhausted.
     */
    private function awaitConfirmation(string $signature): void
    {
        $rpc = $this->rpc();
        for ($attempt = 0; $attempt < $this->confirmationAttempts; $attempt += 1) {
            $statuses = $rpc->getSignatureStatuses([$signature]);
            $status = $statuses[0] ?? null;
            if (is_array($status)) {
                if (($status['err'] ?? null) !== null) {
                    throw new RuntimeException(
                        "Transaction $signature failed: " . json_encode($status['err'], JSON_THROW_ON_ERROR),
                    );
                }
                $confirmationStatus = $status['confirmationStatus'] ?? null;
                if ($confirmationStatus === 'confirmed' || $confirmationStatus === 'finalized') {
                    return;
                }
            }
            usleep($this->confirmationDelayMicros);
        }
        throw new RuntimeException("Timed out waiting for transaction $signature");
    }

    private function caip2(): string
    {
        return $this->config->network->caip2();
    }

    /**
     * Decode a base64(JSON) x402 credential header into its envelope array.
     * Standard (padded) base64, matching the rust producer's STANDARD engine.
     *
     * @return array<string, mixed>
     */
    private function decodeCredential(string $header): array
    {
        $decoded = base64_decode($header, true);
        if ($decoded === false) {
            throw new InvalidProofException('invalid_exact_svm_payload_signature_base64');
        }
        try {
            $envelope = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw new InvalidProofException('invalid_exact_svm_payload_signature_json');
        }
        if (!is_array($envelope)) {
            throw new InvalidProofException('invalid_exact_svm_payload_envelope');
        }
        return $envelope;
    }

    /**
     * Validate a canonical (current-wire) credential against the server offer.
     *
     * The credential echoes the full `accepted` requirement it claims to be
     * paying for; we identity-key match it against the route's offer
     * (scheme/network/asset/payTo + extra.feePayer/tokenProgram/memo) so a
     * credential that lies about its requirement is rejected before settlement.
     * Mirrors the rust v2 arm + cross-SDK PR #138 alignment.
     *
     * @param array<string, mixed> $envelope
     * @param array<string, mixed> $offer
     */
    private function matchCanonicalCredential(array $envelope, array $offer): void
    {
        $accepted = $envelope['accepted'] ?? null;
        if (!is_array($accepted)) {
            throw new InvalidProofException('invalid_exact_svm_payload_envelope');
        }
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
    }

    /**
     * Validate a legacy-wire credential.
     *
     * The legacy wire carries no `accepted` object: it commits only to a
     * top-level scheme + plain network slug (siblings of `payload`). The
     * server binds scheme === "exact" and normalizes the plain slug to a
     * CAIP-2 chain id, gating it against the route's pinned network. The inner
     * transaction is then checked against the server-built offer with the
     * IDENTICAL MUST-checks (compute budget, transferChecked, fee-payer,
     * memo) the canonical path runs. Mirrors the rust v1 arm
     * (server/exact.rs parse_payment_signature + find_matching_requirement).
     *
     * @param array<string, mixed> $envelope
     */
    private function matchLegacyCredential(array $envelope): void
    {
        $scheme = $envelope['scheme'] ?? null;
        if ($scheme !== self::EXACT_SCHEME) {
            throw new InvalidProofException(
                'pay_kit: charge_request_mismatch: unsupported scheme '
                . (is_scalar($scheme) ? (string) $scheme : 'unknown'),
            );
        }
        $network = $envelope['network'] ?? null;
        if (!is_string($network) || $network === '') {
            throw new InvalidProofException('invalid_exact_svm_payload_envelope');
        }
        $normalized = self::caip2ForCluster($network);
        $expected   = $this->caip2();
        if ($normalized !== $expected) {
            throw new InvalidProofException(
                "Network mismatch: expected $expected, got $network",
            );
        }
    }

    /**
     * Pick the network to echo in the settlement response: the canonical
     * wire's `accepted.network` (CAIP-2) or the legacy wire's top-level plain
     * network slug, falling back to the route's CAIP-2 id.
     *
     * @param array<string, mixed> $envelope
     */
    private function settlementNetwork(array $envelope): string
    {
        $accepted = $envelope['accepted'] ?? null;
        if (is_array($accepted) && is_string($accepted['network'] ?? null) && $accepted['network'] !== '') {
            return $accepted['network'];
        }
        if (is_string($envelope['network'] ?? null) && $envelope['network'] !== '') {
            return $envelope['network'];
        }
        return $this->caip2();
    }

    /**
     * Normalize a legacy v1 plain network slug (or any cluster slug / CAIP-2
     * id) to its canonical CAIP-2 chain identifier. Mirrors the rust spine
     * `caip2_network_for_cluster`: localnet collapses to the devnet CAIP-2 id
     * by convention (Surfpool clones mainnet state but reuses devnet genesis).
     */
    private static function caip2ForCluster(string $cluster): string
    {
        return match ($cluster) {
            self::CAIP2_MAINNET, 'solana', 'mainnet', 'mainnet-beta' => self::CAIP2_MAINNET,
            self::CAIP2_TESTNET, 'testnet', 'solana-testnet'         => self::CAIP2_TESTNET,
            'devnet', 'localnet'                                     => self::CAIP2_DEVNET,
            self::CAIP2_DEVNET, 'solana-devnet'                      => self::CAIP2_DEVNET,
            default                                                  => self::CAIP2_MAINNET,
        };
    }
}
