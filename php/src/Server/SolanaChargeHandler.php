<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use InvalidArgumentException;
use RuntimeException;
use Throwable;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Store\MemoryStore;
use SolanaMpp\Store\Store;
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
    private const REPLAY_KEY_PREFIX = 'solana-charge:consumed:';

    private readonly PaymentVerifier $verifier;
    private readonly TransactionPayloadVerifier $transactionVerifier;
    private readonly Store $replayStore;

    /**
     * @param ChargeServer $challenges Low-level challenge signing + credential
     *        parsing (created with a `blockhashProvider` if you want
     *        `recentBlockhash` pre-fetched into every 402).
     * @param RpcClient $rpc RPC endpoint used for broadcast and confirmation.
     * @param ?Keypair $feePayer When set, the handler adds the server's
     *        signature to the fee-payer slot before broadcast. Required for
     *        charge requests that advertise `methodDetails.feePayer = true`.
     * @param string $network Network identifier used for the Surfpool
     *        blockhash sanity check. Defaults to `mainnet`; the legacy
     *        `mainnet-beta` spelling is also accepted. Set to `localnet`
     *        when running against a Surfpool sandbox.
     * @param string $settlementHeader Name of the response header carrying
     *        the on-chain signature. The convention is
     *        `x-payment-settlement-signature`.
     * @param ?PaymentVerifier $verifier Override the default transaction
     *        verifier. Defaults to {@see SolanaChargeTransactionVerifier}.
     * @param ?TransactionPayloadVerifier $transactionVerifier Override the
     *        raw transaction verifier used after fetching push-mode
     *        transactions by signature. Defaults to the same verifier
     *        when it implements {@see TransactionPayloadVerifier}, otherwise
     *        a fresh {@see SolanaChargeTransactionVerifier}.
     * @param int $confirmationAttempts How many times to poll
     *        `getSignatureStatuses` before giving up. 40 attempts at the
     *        default delay = 10 seconds.
     * @param int $confirmationDelayMicros Sleep between polls in microseconds.
     * @param ?Store $replayStore Replay-protection store. Defaults to an
     *        in-process {@see MemoryStore}; production deployments should
     *        inject a shared atomic store (Redis, Postgres) so replay
     *        protection survives restarts and worker pools.
     */
    public function __construct(
        private readonly ChargeServer $challenges,
        private readonly RpcClient $rpc,
        private readonly ?Keypair $feePayer = null,
        private readonly string $network = 'mainnet',
        private readonly string $settlementHeader = 'x-payment-settlement-signature',
        ?PaymentVerifier $verifier = null,
        ?TransactionPayloadVerifier $transactionVerifier = null,
        private readonly int $confirmationAttempts = 40,
        private readonly int $confirmationDelayMicros = 250_000,
        ?Store $replayStore = null,
    ) {
        $this->verifier = $verifier ?? new SolanaChargeTransactionVerifier();
        $this->transactionVerifier = $transactionVerifier
            ?? ($this->verifier instanceof TransactionPayloadVerifier ? $this->verifier : new SolanaChargeTransactionVerifier());
        $this->replayStore = $replayStore ?? new MemoryStore();
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
     * Dispatch on credential payload shape: pull mode (`type=transaction`,
     * server broadcasts) or push mode (`type=signature`, client already
     * broadcast on-chain).
     *
     * Push-mode B34: routes that advertise `methodDetails.feePayer = true`
     * MUST NOT accept push credentials. A push credential references an
     * already-landed transaction that the client has already paid the fee
     * for, defeating the point of a server-funded charge. The B34 reject
     * fires BEFORE any RPC call so a partially validated push credential
     * never touches the network. Mirrors Rust `charge.rs::settle()`,
     * Ruby `verifier.rb`, Lua `verify_signature`, and Python `_settle_push`.
     */
    private function settleCredentialPayload(Credential $credential, ChargeRequest $request): string
    {
        $methodDetails = is_array($request->methodDetails) ? $request->methodDetails : [];

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

        if (($methodDetails['feePayer'] ?? false) === true) {
            throw new RuntimeException('Push-mode credentials are not allowed when the route uses a server-side fee payer');
        }

        $transactionBase64 = $this->fetchSettledTransaction($signature);
        $verification = $this->transactionVerifier->verifyTransactionPayload($transactionBase64, $request);
        if (!$verification->ok) {
            throw new RuntimeException($verification->reason);
        }

        // L8 push-mode ordering. Pull-mode broadcasts first then consumes
        // between broadcast and await so a crashed await cannot double-pay
        // on retry. Push-mode has no broadcast step (the client already
        // broadcast and confirmed), so the on-chain artifact is fetched +
        // verified first, then the signature is consumed. A replayed push
        // credential trips the consume guard on the second attempt.
        $this->consumeSignature($signature);
        return $signature;
    }

    /**
     * Fetch a confirmed transaction by signature and return its base64 wire
     * form. Polls `getTransaction` (commitment=confirmed) up to
     * `confirmationAttempts` times to ride out the brief gap between the
     * client's `sendTransaction` accept and the cluster surfacing the
     * settled transaction.
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
            if (!is_array($meta)) {
                throw new RuntimeException('getTransaction response is missing transaction metadata');
            }
            if (($meta['err'] ?? null) !== null) {
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

    /**
     * Co-sign (if a fee-payer is configured), broadcast, claim the signature
     * in the replay store, then wait for confirmation. Returns the on-chain
     * signature.
     *
     * `consumeSignature` is called between broadcast and confirmation
     * polling on purpose. If the server crashes or the polling times out
     * after `sendRawTransaction` accepted the transaction, the signature
     * has already landed and must not be re-settled by a retry of the same
     * credential. See PR #85 Greptile P1 and audit gap G05.
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

        $this->consumeSignature($signature);
        $this->awaitConfirmation($signature);
        return $signature;
    }

    /**
     * Reserve the signature in the replay store. Throws on replay attempts.
     */
    private function consumeSignature(string $signature): void
    {
        $key = self::REPLAY_KEY_PREFIX . $signature;
        if (!$this->replayStore->putIfAbsent($key, true)) {
            throw new RuntimeException("Transaction signature already consumed: $signature");
        }
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
