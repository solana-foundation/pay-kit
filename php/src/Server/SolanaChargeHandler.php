<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use InvalidArgumentException;
use RuntimeException;
use Throwable;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Rpc\RpcClient;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Transaction\VersionedTransaction;
use SolanaPhpSdk\Util\Base58;

/**
 * High-level Solana charge server: verify → optional co-sign → broadcast →
 * confirm → receipt, in one call.
 *
 * Composes the lower-level {@see ChargeServer} (challenge signing/verification)
 * with a Solana RPC client and an optional fee-payer keypair. Callers feed in
 * the request's `Authorization` header and a `ChargeRequest`; they get back
 * either {@see PaymentRequiredResponse} (402, with `www-authenticate`) or
 * {@see ChargeSettlement} (200, with `payment-receipt` + on-chain signature).
 *
 * Both result types expose `status` / `headers` / `body`, so the HTTP layer
 * just emits them uniformly.
 */
final class SolanaChargeHandler
{
    private readonly PaymentVerifier $verifier;
    private readonly TransactionPayloadVerifier $transactionVerifier;
    private readonly ReplayStore $replayStore;

    /**
     * @param ChargeServer $challenges Low-level challenge signing + credential
     *        parsing (created with a `blockhashProvider` if you want
     *        `recentBlockhash` pre-fetched into every 402).
     * @param RpcClient $rpc RPC endpoint used for broadcast and confirmation.
     * @param ?Keypair $feePayer When set, the handler adds the server's
     *        signature to the fee-payer slot before broadcast. Required for
     *        charge requests that advertise `methodDetails.feePayer = true`.
     * @param string $network Network identifier used for the Surfpool
     *        blockhash sanity check. Defaults to `mainnet-beta`; set to
     *        `localnet` when running against a Surfpool sandbox.
     * @param string $settlementHeader Name of the response header carrying
     *        the on-chain signature. The convention is
     *        `x-payment-settlement-signature`.
     * @param ?PaymentVerifier $verifier Override the default transaction
     *        verifier. Defaults to {@see SolanaChargeTransactionVerifier}.
     * @param ?TransactionPayloadVerifier $transactionVerifier Override the
     *        raw transaction verifier used after fetching push-mode
     *        transactions by signature.
     * @param ?ReplayStore $replayStore Replay store keyed by
     *        `solana-charge:consumed:<signature>`.
     * @param int $confirmationAttempts How many times to poll
     *        `getSignatureStatuses` before giving up. 40 attempts at the
     *        default delay = 10 seconds.
     * @param int $confirmationDelayMicros Sleep between polls in microseconds.
     */
    public function __construct(
        private readonly ChargeServer $challenges,
        private readonly RpcClient $rpc,
        private readonly ?Keypair $feePayer = null,
        private readonly string $network = 'mainnet-beta',
        private readonly string $settlementHeader = 'x-payment-settlement-signature',
        ?PaymentVerifier $verifier = null,
        ?TransactionPayloadVerifier $transactionVerifier = null,
        ?ReplayStore $replayStore = null,
        private readonly int $confirmationAttempts = 40,
        private readonly int $confirmationDelayMicros = 250_000,
    ) {
        $this->verifier = $verifier ?? new SolanaChargeTransactionVerifier();
        $this->transactionVerifier = $transactionVerifier
            ?? ($this->verifier instanceof TransactionPayloadVerifier ? $this->verifier : new SolanaChargeTransactionVerifier());
        $this->replayStore = $replayStore ?? new MemoryReplayStore();
    }

    /**
     * Base58 pubkey of the configured fee-payer signer, or null when the
     * handler is operating in client-pays-fees mode.
     */
    public function feePayerPubkey(): ?string
    {
        return $this->feePayer?->getPublicKey()->toBase58();
    }

    /**
     * Process one inbound request.
     *
     * Returns 402 ({@see PaymentRequiredResponse}) when the credential is
     * missing, malformed, fails protocol checks, or fails on-chain. Returns
     * 200 ({@see ChargeSettlement}) only after a transaction has been
     * broadcast and confirmed.
     */
    public function handle(?string $authorization, ChargeRequest $request): PaymentRequiredResponse|ChargeSettlement
    {
        if ($authorization === null || $authorization === '') {
            return $this->challenges->paymentRequiredResponse($request);
        }

        $result = $this->challenges->verifyAuthorizationHeader(
            $authorization,
            $this->verifier,
            expectedRequest: $request,
        );
        if (!$result->ok) {
            return $this->challenges->paymentRequiredResponse($request, $result->reason);
        }

        $credential = $result->credential;
        $challenge = $result->challenge;
        if ($credential === null || $challenge === null) {
            return $this->challenges->paymentRequiredResponse($request, 'verified result is missing credential or challenge');
        }

        try {
            $signature = $this->settleCredentialPayload($credential, $request);
            $this->consumeSignature($signature);
        } catch (Throwable $error) {
            return $this->challenges->paymentRequiredResponse($request, $error->getMessage());
        }

        $receipt = $this->challenges->createReceiptHeaderForReference(
            challenge: $challenge,
            reference: $signature,
            externalId: $request->externalId,
        );

        return new ChargeSettlement(
            status: 200,
            headers: [
                'content-type' => 'application/json',
                'payment-receipt' => $receipt,
                $this->settlementHeader => $signature,
            ],
            body: ['ok' => true, 'paid' => true],
            signature: $signature,
            receiptHeader: $receipt,
        );
    }

    /**
     * Settle pull-mode transactions or verify push-mode transaction signatures.
     */
    private function settleCredentialPayload(Credential $credential, ChargeRequest $request): string
    {
        $transaction = $credential->payload['transaction'] ?? null;
        if (is_string($transaction) && $transaction !== '') {
            if ($this->isSurfpoolMismatch($transaction)) {
                throw new RuntimeException("Signed with a Surfpool localnet blockhash but the server expects {$this->network}.");
            }

            return $this->settle($transaction);
        }

        $signature = $credential->payload['signature'] ?? null;
        if (!is_string($signature) || $signature === '') {
            throw new InvalidArgumentException('missing transaction or signature payload');
        }

        $transactionBase64 = $this->fetchSettledTransaction($signature);
        $result = $this->transactionVerifier->verifyTransactionPayload($transactionBase64, $request);
        if (!$result->ok) {
            throw new RuntimeException($result->reason);
        }

        return $signature;
    }

    /**
     * Co-sign (if a fee-payer is configured), broadcast, and wait for
     * confirmation. Returns the on-chain signature.
     */
    private function settle(string $transactionBase64): string
    {
        $wire = base64_decode($transactionBase64, true);
        if ($wire === false || $wire === '') {
            throw new InvalidArgumentException('invalid transaction payload');
        }

        if (VersionedTransaction::peekVersion($wire) === 'legacy') {
            $tx = Transaction::deserialize($wire);
            if ($this->feePayer !== null) {
                $tx->partialSign($this->feePayer);
            }
            $signed = $tx->serialize();
        } else {
            $tx = VersionedTransaction::deserialize($wire);
            if ($this->feePayer !== null) {
                $tx->partialSign($this->feePayer);
            }
            $signed = $tx->serialize();
        }

        $signature = $this->rpc->sendRawTransaction($signed, [
            'encoding' => 'base64',
            'skipPreflight' => false,
            'preflightCommitment' => 'confirmed',
        ]);

        $this->awaitConfirmation($signature);
        return $signature;
    }

    private function awaitConfirmation(string $signature): void
    {
        for ($attempt = 0; $attempt < $this->confirmationAttempts; $attempt += 1) {
            $statuses = $this->rpc->getSignatureStatuses([$signature]);
            $status = $statuses[0] ?? null;
            if (is_array($status)) {
                if (($status['err'] ?? null) !== null) {
                    throw new RuntimeException("Transaction $signature failed: " . json_encode($status['err'], JSON_THROW_ON_ERROR));
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

    /**
     * Fetch a confirmed transaction by signature and return its base64 wire form.
     */
    private function fetchSettledTransaction(string $signature): string
    {
        for ($attempt = 0; $attempt < $this->confirmationAttempts; $attempt += 1) {
            /** @var mixed $transaction */
            $transaction = $this->rpc->call('getTransaction', [
                $signature,
                [
                    'encoding' => 'base64',
                    'commitment' => 'confirmed',
                    'maxSupportedTransactionVersion' => 0,
                ],
            ]);
            if ($transaction === null) {
                usleep($this->confirmationDelayMicros);
                continue;
            }
            if (!is_array($transaction)) {
                throw new RuntimeException('Invalid getTransaction response');
            }
            $meta = $transaction['meta'] ?? null;
            if (is_array($meta) && ($meta['err'] ?? null) !== null) {
                throw new RuntimeException('Transaction ' . $signature . ' failed: ' . json_encode($meta['err'], JSON_THROW_ON_ERROR));
            }
            $wire = $transaction['transaction'] ?? null;
            if (is_array($wire) && isset($wire[0]) && is_string($wire[0]) && $wire[0] !== '') {
                return $wire[0];
            }
            if (is_string($wire) && $wire !== '') {
                return $wire;
            }
            throw new RuntimeException('getTransaction response is missing base64 transaction data');
        }

        throw new RuntimeException("Timed out waiting for transaction $signature");
    }

    private function consumeSignature(string $signature): void
    {
        $key = "solana-charge:consumed:$signature";
        if (!$this->replayStore->consume($key)) {
            throw new RuntimeException('Transaction signature already consumed');
        }
    }

    /**
     * Mirror Rust's `check_network_blockhash`: a Surfpool-prefixed blockhash
     * is only valid on `localnet`. Reject `localnet`-signed transactions when
     * the server is configured for any other network.
     */
    private function isSurfpoolMismatch(string $transactionBase64): bool
    {
        if ($this->network === 'localnet') {
            return false;
        }
        try {
            $wire = base64_decode($transactionBase64, true);
            if ($wire === false) {
                return false;
            }
            // Legacy `Message` stores the blockhash as raw 32 bytes; v0
            // `MessageV0` stores it as a base58 string. Normalize to base58
            // before checking the Surfpool prefix.
            $blockhash = VersionedTransaction::peekVersion($wire) === 'legacy'
                ? Base58::encode(Transaction::deserialize($wire)->message->recentBlockhash)
                : VersionedTransaction::deserialize($wire)->message->recentBlockhash;
        } catch (Throwable) {
            return false;
        }
        return str_starts_with($blockhash, 'SURFNET');
    }
}
