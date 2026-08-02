<?php

declare(strict_types=1);

namespace PayKit\Protocols\X402\Upto;

use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\PayCore\PaymentChannels;
use PayKit\PayCore\Rpc\RpcGateway;
use PayKit\PayCore\Rpc\SolanaRpcGateway;
use SolanaPhpSdk\Keypair\Keypair;
use PayKit\PayCore\Solana\Mints;
use Psr\Http\Message\ServerRequestInterface;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Rpc\RpcClient;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use Throwable;

/**
 * x402 `upto` (Solana) server engine — payment-channel profile.
 *
 * Flow (mirrors Rust/Go/Python):
 *   1. {@see challengeHeaders}/{@see acceptsEntry} — advertise the ceiling.
 *   2. {@see verifyOpenPayload} — validate payload + open instruction shape.
 *   3. {@see verifyOpenAndBroadcast} — cosign as fee payer, broadcast open, confirm.
 *   4. settle_and_seal + distribute — later slice after open is live.
 */
final class Engine
{
    private const PAYMENT_REQUIRED_HEADER = 'payment-required';
    private const PAYMENT_SIGNATURE_HEADER = 'payment-signature';
    private const PAYMENT_LEGACY_HEADER = 'x-payment';

    /** @var \Closure():?array{blockhash: string, slot?: string}|null */
    private $chainHintsProvider = null;

    /**
     * @param ?\Closure():?array{blockhash: string, slot?: string} $chainHintsProvider
     *        Test hook for recentBlockhash / recentSlot without RPC.
     */
    public function __construct(
        private readonly Config $config,
        ?\Closure $chainHintsProvider = null,
        private ?RpcGateway $rpc = null,
        private readonly int $confirmationAttempts = 40,
        private readonly int $confirmationDelayMicros = 250_000,
    ) {
        $this->chainHintsProvider = $chainHintsProvider;
    }

    /**
     * Single accepts[] entry for an `upto` challenge.
     *
     * @return array<string,mixed>
     */
    public function acceptsEntry(Gate $gate, ServerRequestInterface $request): array
    {
        $coin = $gate->amount->primaryCoin()?->value ?? $this->config->stablecoins[0]->value;
        $asset = Mints::resolve($coin, $this->config->network->mintsLabel()) ?? $coin;
        $tokenProgram = Mints::tokenProgramFor($coin, $this->config->network->mintsLabel());
        $payTo = $gate->payTo ?? $this->config->effectiveRecipient();
        // Match Exact adapter: Price is human units × 1e6 → base units string.
        $amount = (string) $gate->total()->amount->multipliedBy(1_000_000)->toInt();
        $signer = $this->config->effectiveX402Signer();
        $feePayer = $signer?->pubkey() ?? '';
        // Operator holds both seats: fee payer (lifecycle) + receiver authorizer
        // (voucher signer). Matches createPayKit / Rust X402Upto.
        $extra = [
            'decimals'           => 6,
            'tokenProgram'       => $tokenProgram,
            'feePayer'           => $feePayer,
            'receiverAuthorizer' => $feePayer,
            'withdrawDelay'      => Types::DEFAULT_WITHDRAW_DELAY_SECONDS,
        ];
        $hints = $this->fetchChainHints();
        if ($hints !== null) {
            if (($hints['blockhash'] ?? '') !== '') {
                $extra['recentBlockhash'] = $hints['blockhash'];
            }
            if (isset($hints['slot']) && $hints['slot'] !== '') {
                $extra['recentSlot'] = (string) $hints['slot'];
            }
        }

        return [
            'protocol'          => 'x402',
            'scheme'            => Types::SCHEME,
            'network'           => $this->caip2(),
            'asset'             => $asset,
            'amount'            => $amount,
            'maxAmountRequired' => $amount,
            'payTo'             => $payTo,
            'maxTimeoutSeconds' => Types::DEFAULT_MAX_TIMEOUT_SECONDS,
            'extra'             => $extra,
        ];
    }

    /**
     * @return array<string,string>
     */
    public function challengeHeaders(Gate $gate, ServerRequestInterface $request): array
    {
        $challenge = [
            'x402Version' => Types::X402_VERSION,
            'resource'    => ['type' => 'http', 'url' => $request->getUri()->getPath()],
            'accepts'     => [$this->acceptsEntry($gate, $request)],
        ];
        $encoded = base64_encode(
            json_encode($challenge, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
        );

        return [self::PAYMENT_REQUIRED_HEADER => $encoded];
    }

    /**
     * Decode and structurally validate an upto PAYMENT-SIGNATURE open.
     *
     * Does not broadcast yet — returns the verified payload + requirement
     * binding for the settle phase. Callers that need on-chain open should
     * use a follow-up that cosigns + sends (payment-channel builders).
     *
     * @param array<string,mixed> $requirements Route-pinned accepts[] entry
     *
     * @return array{
     *   payload: array<string,mixed>,
     *   requirements: array<string,mixed>,
     *   maxBaseUnits: int,
     *   payer: string,
     *   channelId: string
     * }
     *
     * @throws InvalidProofException
     */
    public function verifyOpenPayload(ServerRequestInterface $request, array $requirements): array
    {
        $header = $this->paymentHeader($request);
        if ($header === null) {
            throw new InvalidProofException('missing_x402_payment_header');
        }

        $raw = base64_decode($header, true);
        if ($raw === false || $raw === '') {
            throw new InvalidProofException('invalid_x402_payment_header');
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (Throwable $e) {
            throw new InvalidProofException('invalid_x402_payment_header', 0, $e);
        }
        if (!is_array($decoded) || !isset($decoded['payload']) || !is_array($decoded['payload'])) {
            throw new InvalidProofException('invalid_x402_payment_header');
        }

        /** @var array<string,mixed> $payload */
        $payload = $decoded['payload'];
        $extra = is_array($requirements['extra'] ?? null) ? $requirements['extra'] : [];
        $receiverAuthorizer = (string) ($extra['receiverAuthorizer'] ?? '');
        if ($receiverAuthorizer === '') {
            throw new InvalidProofException('upto requirement missing receiverAuthorizer');
        }

        Verify::verifyUptoPayload($payload, $requirements, $receiverAuthorizer, time());

        // payment-channel profile requires a pull-style open transaction; push
        // (signature-only) is not accepted by this engine.
        $openTx = (string) ($payload['openTransaction'] ?? '');
        if ($openTx === '') {
            throw new InvalidProofException(
                'upto payment-channel payload missing openTransaction',
            );
        }
        $this->validateOpenTransaction(
            $openTx,
            $payload,
            $requirements,
            $receiverAuthorizer,
        );

        $maxBaseUnits = Verify::parseBaseUnits((string) $requirements['amount'], 'amount');

        return [
            'payload'       => $payload,
            'requirements'  => $requirements,
            'maxBaseUnits'  => $maxBaseUnits,
            'payer'         => (string) ($payload['from'] ?? ''),
            'channelId'     => (string) ($payload['channelId'] ?? ''),
        ];
    }

    /**
     * Enforce actual ≤ max. Full settle_and_seal broadcast is the next slice.
     *
     * @throws InvalidProofException
     */
    public function assertSettlementAmount(int $actualBaseUnits, int $maxBaseUnits): void
    {
        Verify::assertSettlementWithinCeiling($actualBaseUnits, $maxBaseUnits);
    }

    /**
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $requirements
     *
     * @throws InvalidProofException
     */
    private function validateOpenTransaction(
        string $transactionBase64,
        array $payload,
        array $requirements,
        string $receiverAuthorizer,
    ): void {
        $raw = base64_decode($transactionBase64, true);
        if ($raw === false || $raw === '') {
            throw new InvalidProofException('invalid open transaction base64');
        }
        try {
            $tx = VersionedTransaction::deserialize($raw);
        } catch (Throwable $e) {
            throw new InvalidProofException('invalid open transaction parse', 0, $e);
        }

        $message = $tx->message;
        // Match SolanaChargeTransactionVerifier: open must not pull accounts
        // from address lookup tables (static keys only).
        if (($message->addressTableLookups ?? []) !== []) {
            throw new InvalidProofException(
                'v0 address lookup tables are not supported on upto open transactions',
            );
        }
        $accountKeys = array_map(
            static fn (PublicKey $k): string => (string) $k,
            $message->staticAccountKeys,
        );
        $instructions = [];
        foreach ($message->compiledInstructions as $ix) {
            $instructions[] = [
                'programIdIndex' => (int) $ix->programIdIndex,
                'accounts'       => array_map('intval', $ix->accountKeyIndexes),
                'data'           => is_string($ix->data) ? $ix->data : (string) $ix->data,
            ];
        }

        $extra = is_array($requirements['extra'] ?? null) ? $requirements['extra'] : [];
        $feePayer = $this->requirePubkey(
            (string) ($extra['feePayer'] ?? $receiverAuthorizer),
            'feePayer',
        );
        $receiver = $this->requirePubkey($receiverAuthorizer, 'receiverAuthorizer');
        $payer = $this->requirePubkey((string) ($payload['from'] ?? ''), 'from');
        // Channel payee is the fee payer (zero-share lifecycle seat) for upto.
        $payee = $feePayer;
        $mint = $this->requirePubkey((string) ($requirements['asset'] ?? ''), 'asset');
        $tokenProgram = $this->requirePubkey(
            (string) ($extra['tokenProgram'] ?? PaymentChannels::tokenProgramId()),
            'tokenProgram',
        );
        $channelId = $this->requirePubkey((string) ($payload['channelId'] ?? ''), 'channelId');
        $maxAmount = Verify::parseBaseUnits((string) $requirements['amount'], 'amount');
        $withdrawDelay = (int) ($extra['withdrawDelay'] ?? Types::DEFAULT_WITHDRAW_DELAY_SECONDS);
        $recentSlot = isset($extra['recentSlot']) ? (int) $extra['recentSlot'] : null;

        Verify::validateUptoOpenInstruction(
            $accountKeys,
            $instructions,
            new PublicKey(PaymentChannels::PROGRAM_ID),
            $feePayer,
            $receiver,
            $payer,
            $payee,
            $mint,
            $tokenProgram,
            $channelId,
            $maxAmount,
            $withdrawDelay,
            (string) ($payload['nonce'] ?? ''),
            (string) ($payload['openSlot'] ?? ''),
            $recentSlot,
        );

        // Greptile P1: rentPayer on the open ix can match the operator while
        // the tx fee payer (static account key 0) is someone else — cosign
        // would then fail at broadcast. Bind fee payer here like Python.
        if ($accountKeys === [] || $accountKeys[0] !== (string) $feePayer) {
            throw new InvalidProofException(
                'open transaction fee payer must be the advertised fee payer',
            );
        }
    }


    /**
     * Validate open credential, cosign as fee payer, broadcast, and confirm.
     *
     * @param array<string,mixed> $requirements
     * @return array{
     *   payload: array<string,mixed>,
     *   requirements: array<string,mixed>,
     *   maxBaseUnits: int,
     *   payer: string,
     *   channelId: string,
     *   openSignature: string
     * }
     *
     * @throws InvalidProofException
     */
    public function verifyOpenAndBroadcast(ServerRequestInterface $request, array $requirements): array
    {
        $verified = $this->verifyOpenPayload($request, $requirements);
        $openTx = (string) ($verified['payload']['openTransaction'] ?? '');
        $sig = $this->cosignAndBroadcastOpenTransaction($openTx);
        $verified['openSignature'] = $sig;

        return $verified;
    }

    /**
     * Cosign the client-built open as the advertised fee payer and broadcast.
     *
     * The client signed the payer slot; the operator (fee payer / rentPayer)
     * completes the missing signature then sends the wire transaction.
     *
     * @throws InvalidProofException
     */
    public function cosignAndBroadcastOpenTransaction(string $transactionBase64): string
    {
        $signer = $this->config->effectiveX402Signer();
        if ($signer === null) {
            throw new InvalidProofException('upto cosign requires an x402 operator signer');
        }

        $raw = base64_decode($transactionBase64, true);
        if ($raw === false || $raw === '') {
            throw new InvalidProofException('invalid open transaction base64');
        }
        try {
            $tx = VersionedTransaction::deserialize($raw);
        } catch (Throwable $e) {
            throw new InvalidProofException('invalid open transaction parse', 0, $e);
        }

        $feePayer = $this->requirePubkey($signer->pubkey(), 'feePayer');
        $keys = $tx->message->staticAccountKeys;
        if ($keys === [] || (string) $keys[0] !== (string) $feePayer) {
            throw new InvalidProofException(
                'open transaction fee payer must be the advertised fee payer',
            );
        }

        try {
            $kp = Keypair::fromSecretKey($signer->secretKey());
            $tx->partialSign($kp);
            $wire = $tx->serialize(verifySignatures: false);
        } catch (Throwable $e) {
            throw new InvalidProofException('upto cosign failed: ' . $e->getMessage(), 0, $e);
        }

        $rpc = $this->rpc();
        try {
            $sig = $rpc->sendRawTransaction($wire, [
                'encoding'              => 'base64',
                'skipPreflight'         => false,
                'preflightCommitment'   => 'confirmed',
            ]);
        } catch (Throwable $e) {
            throw new InvalidProofException(
                'pay_kit: invalid proof: open broadcast failed: ' . $e->getMessage(),
                0,
                $e,
            );
        }
        if (!is_string($sig) || $sig === '') {
            throw new InvalidProofException('pay_kit: empty open broadcast result');
        }

        try {
            $this->awaitConfirmation($sig);
        } catch (Throwable $e) {
            throw new InvalidProofException(
                'pay_kit: invalid proof: open not confirmed: ' . $e->getMessage(),
                0,
                $e,
            );
        }

        return $sig;
    }

    private function rpc(): RpcGateway
    {
        if ($this->rpc !== null) {
            return $this->rpc;
        }
        if ($this->config->rpcUrl === '') {
            throw new InvalidProofException('upto broadcast requires Config::$rpcUrl or an injected RpcGateway');
        }

        return $this->rpc = new SolanaRpcGateway(new RpcClient($this->config->rpcUrl));
    }

    /**
     * @throws \RuntimeException
     */
    private function awaitConfirmation(string $signature): void
    {
        $rpc = $this->rpc();
        for ($attempt = 0; $attempt < $this->confirmationAttempts; $attempt += 1) {
            $statuses = $rpc->getSignatureStatuses([$signature]);
            $status = $statuses[0] ?? null;
            if (is_array($status)) {
                if (($status['err'] ?? null) !== null) {
                    throw new \RuntimeException(
                        "Transaction $signature failed: " . json_encode($status['err'], JSON_THROW_ON_ERROR),
                    );
                }
                $confirmationStatus = $status['confirmationStatus'] ?? null;
                if ($confirmationStatus === 'confirmed' || $confirmationStatus === 'finalized') {
                    return;
                }
            }
            if ($this->confirmationDelayMicros > 0 && $attempt + 1 < $this->confirmationAttempts) {
                usleep($this->confirmationDelayMicros);
            }
        }
        throw new \RuntimeException("Transaction $signature not confirmed after {$this->confirmationAttempts} attempts");
    }

    private function requirePubkey(string $value, string $label): PublicKey
    {
        if ($value === '') {
            throw new InvalidProofException("invalid {$label} public key: empty");
        }
        try {
            return new PublicKey($value);
        } catch (Throwable $e) {
            throw new InvalidProofException("invalid {$label} public key", 0, $e);
        }
    }

    private function paymentHeader(ServerRequestInterface $request): ?string
    {
        $headers = $request->getHeaders();
        foreach ([self::PAYMENT_SIGNATURE_HEADER, self::PAYMENT_LEGACY_HEADER] as $name) {
            foreach ($headers as $key => $values) {
                if (strtolower((string) $key) === $name && isset($values[0]) && $values[0] !== '') {
                    return $values[0];
                }
            }
        }

        return null;
    }

    /**
     * @return ?array{blockhash: string, slot?: string}
     */
    private function fetchChainHints(): ?array
    {
        if ($this->chainHintsProvider !== null) {
            try {
                $value = ($this->chainHintsProvider)();

                return is_array($value) ? $value : null;
            } catch (Throwable) {
                return null;
            }
        }
        if ($this->config->rpcUrl === '') {
            return null;
        }
        try {
            $rpc = new RpcClient($this->config->rpcUrl);
            $result = $rpc->getLatestBlockhash();
            $blockhash = is_array($result) && isset($result['blockhash'])
                ? (string) $result['blockhash']
                : '';
            if ($blockhash === '') {
                return null;
            }
            $hints = ['blockhash' => $blockhash];
            // Optional: getSlot when the client is available.
            if (method_exists($rpc, 'getSlot')) {
                try {
                    $slot = $rpc->getSlot();
                    if (is_int($slot) || (is_string($slot) && $slot !== '')) {
                        $hints['slot'] = (string) $slot;
                    }
                } catch (Throwable) {
                    // recentSlot optional on the challenge
                }
            }

            return $hints;
        } catch (Throwable) {
            return null;
        }
    }

    private function caip2(): string
    {
        return $this->config->network->caip2();
    }
}
