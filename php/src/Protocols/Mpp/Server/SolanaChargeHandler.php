<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

use DateTimeImmutable;
use InvalidArgumentException;
use RuntimeException;
use Throwable;
use PayKit\Exception\SettlementInProgressException;
use PayKit\PayCore\Rpc\RpcGateway;
use PayKit\PayCore\Solana\SignatureConfirmation;
use PayKit\PayCore\Solana\TransactionWire;
use PayKit\PayCore\Rpc\SolanaRpcGateway;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Store\ConsumedSignatures;
use PayKit\Store\MemoryStore;
use PayKit\Store\Store;
use SolanaPhpSdk\Exception\RpcException;
use SolanaPhpSdk\Keypair\Keypair;
use SolanaPhpSdk\Rpc\RpcClient;
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
    private readonly ConsumedSignatures $consumedSignatures;
    private readonly Store $replayStore;

    /**
     * Prefix of the record binding a claimed, possibly broadcast signature to
     * the challenge that broadcast it, so that challenge alone may reconcile
     * it after expiry.
     */
    // Namespaced to this SDK: another SDK's pending record under a look-alike
    // key must never be reconciled (and authorized) here, nor ours there.
    private const PENDING_BINDING_PREFIX = 'pay-kit:php:charge-pending:';
    /** A claimed signature refused for good (preflight, or already processed elsewhere). */
    private const REFUSED_PREFIX = 'pay-kit:php:charge-refused:';

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
    private readonly RpcGateway $rpc;

    public function __construct(
        private readonly ChargeServer $challenges,
        RpcClient|RpcGateway $rpc,
        private readonly ?Keypair $feePayer = null,
        private readonly string $network = 'mainnet',
        private readonly string $settlementHeader = 'x-payment-settlement-signature',
        ?PaymentVerifier $verifier = null,
        ?TransactionPayloadVerifier $transactionVerifier = null,
        private readonly int $confirmationAttempts = 40,
        private readonly int $confirmationDelayMicros = 250_000,
        ?Store $replayStore = null,
        bool $acceptPushMode = false,
    ) {
        $this->rpc = $rpc instanceof RpcGateway ? $rpc : new SolanaRpcGateway($rpc);
        // Push mode (§13.5) is off by default; the default verifier is built
        // with the route's opt-in so a non-opting route rejects push-mode
        // credentials at verification (audit #5).
        $this->verifier = $verifier ?? new SolanaChargeTransactionVerifier(acceptPushMode: $acceptPushMode);
        $this->transactionVerifier = $transactionVerifier
            ?? ($this->verifier instanceof TransactionPayloadVerifier ? $this->verifier : new SolanaChargeTransactionVerifier(acceptPushMode: $acceptPushMode));
        $this->replayStore = $replayStore ?? new MemoryStore();
        $this->consumedSignatures = new ConsumedSignatures($this->replayStore);
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
     * 409 ({@see SettlementPending}) when the payment may have been broadcast
     * and is not resolved yet; the client retries the same credential.
     * Returns 200 ({@see ChargeSettlement}) only after a transaction has been
     * broadcast and confirmed.
     */
    public function handle(?string $authorization, ChargeRequest $request, ?DateTimeImmutable $now = null): PaymentRequiredResponse|ChargeSettlement|SettlementPending
    {
        if ($authorization === null || $authorization === '') {
            return $this->challenges->paymentRequiredResponse($request);
        }

        $result = $this->challenges->verifyAuthorizationHeader(
            $authorization,
            $this->verifier,
            $now,
            expectedRequest: $request,
        );
        $credential = $result->credential;
        $challenge = $result->challenge;
        if (!$result->ok) {
            // An expired challenge never starts a payment, but a retry after
            // a lost broadcast response must still reconcile the charge this
            // same challenge left pending: the payment may have landed.
            if (!$result->expired || $credential === null || $challenge === null) {
                return $this->challenges->paymentRequiredResponse($request, $result->reason);
            }
            try {
                $signature = $this->reconcileExpired($credential, $challenge->id);
            } catch (SettlementInProgressException $pending) {
                return SettlementPending::withDetail($pending->getMessage());
            } catch (Throwable $error) {
                return $this->challenges->paymentRequiredResponse($request, $error->getMessage());
            }
            if ($signature === null) {
                return $this->challenges->paymentRequiredResponse($request, $result->reason);
            }
        } elseif ($credential === null || $challenge === null) {
            return $this->challenges->paymentRequiredResponse($request, 'verified result is missing credential or challenge');
        } else {
            try {
                $signature = $this->settleCredentialPayload($credential, $request, $challenge->id);
            } catch (SettlementInProgressException $pending) {
                return SettlementPending::withDetail($pending->getMessage());
            } catch (Throwable $error) {
                return $this->challenges->paymentRequiredResponse($request, $error->getMessage());
            }
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
    private function settleCredentialPayload(Credential $credential, ChargeRequest $request, string $challengeId): string
    {
        $methodDetails = is_array($request->methodDetails) ? $request->methodDetails : [];

        $transaction = $credential->payload['transaction'] ?? null;
        if (is_string($transaction) && $transaction !== '') {
            if ($this->isSurfpoolMismatch($transaction)) {
                throw new RuntimeException("Signed with a Surfpool localnet blockhash but the server expects {$this->network}.");
            }
            return $this->settle($transaction, $challengeId);
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
     * The transaction is settled under its locally derived signature, never
     * one an RPC node reports. Only a preflight rejection proves the node did
     * not forward it; any other send error (a lost response, a 5xx from a
     * proxy that already forwarded it) leaves the outcome unknown, so the
     * signature is claimed and the charge stays pending
     * ({@see SettlementInProgressException}) instead of failing: a fresh
     * challenge would let the client pay a replacement while the original
     * can still land. A retry of the same credential reconciles the claimed
     * signature against the chain.
     */
    private function settle(string $transactionBase64, string $challengeId): string
    {
        [$signed, $signature] = $this->signedTransaction($transactionBase64);

        // Claim the signature and bind it to this challenge before anything
        // is sent, so a payment that may land always has the record its retry
        // reconciles. Bound only after an ambiguous send, a store failure
        // would leave a claim with nothing to reconcile, and every retry would
        // refuse a payment that may have landed. A failure here sends nothing.
        if (!$this->consumedSignatures->claim($signature)) {
            return $this->reconcileOwn($signature, $challengeId);
        }
        $this->bindPending($signature, $challengeId);

        try {
            $reported = $this->rpc->sendRawTransaction($signed, [
                'encoding' => 'base64',
                'skipPreflight' => false,
                'preflightCommitment' => 'confirmed',
            ]);
        } catch (Throwable $error) {
            if (self::isAlreadyProcessed($error)) {
                // It landed, yet this store held no claim on it: it was
                // settled somewhere this store cannot see. A replay.
                $this->markRefused($signature);
                throw new RuntimeException("Transaction signature already consumed: $signature", 0, $error);
            }
            if (self::isPreflightRejection($error)) {
                // Never forwarded, so it cannot land: the charge failed. The
                // store cannot release the claim, so the refusal is recorded.
                $this->markRefused($signature);
                throw new RuntimeException('Transaction rejected by preflight: ' . $error->getMessage(), 0, $error);
            }
            throw new SettlementInProgressException(
                "Broadcast outcome unknown for transaction $signature; retry the same credential: " . $error->getMessage(),
                0,
                $error,
            );
        }

        if ($reported !== $signature) {
            throw new SettlementInProgressException(
                "RPC reported signature $reported for transaction $signature; retry the same credential",
            );
        }
        $this->awaitConfirmation($signature);
        return $this->authorize($signature);
    }

    /** Record that `$signature` was refused for good, so no retry reconciles it. */
    private function markRefused(string $signature): void
    {
        $this->replayStore->putIfAbsent(self::REFUSED_PREFIX . $signature, true);
    }

    /** Whether a send error says the node already processed this transaction. */
    private static function isAlreadyProcessed(Throwable $error): bool
    {
        return preg_match('/already (been )?processed/i', $error->getMessage()) === 1;
    }

    /**
     * The transaction as this server broadcasts it (co-signed when it pays
     * the fee) and its first signature, which identifies it on chain.
     *
     * @return array{string, string}
     */
    private function signedTransaction(string $transactionBase64): array
    {
        $wire = base64_decode($transactionBase64, true);
        if ($wire === false || $wire === '') {
            throw new InvalidArgumentException('invalid transaction payload');
        }

        $tx = TransactionWire::deserialize($wire);
        if ($this->feePayer !== null) {
            $tx->partialSign($this->feePayer);
        }
        // Every signature must verify before the signature is claimed or the
        // transaction sent. A forged one would otherwise name the charge: the
        // node refuses it without a preflight result, the charge is kept as
        // possibly sent, and a retry would reconcile on the status of
        // whatever landed transaction owns that signature.
        $tx->assertSignaturesVerify();
        $signed = $tx->serialize();
        return [$signed, self::firstSignature($signed)];
    }

    /** Record that `$challengeId` claimed (and may have broadcast) `$signature`. */
    private function bindPending(string $signature, string $challengeId): void
    {
        $this->replayStore->putIfAbsent(self::PENDING_BINDING_PREFIX . $signature . ':' . $challengeId, true);
    }

    /**
     * Reconcile the charge an expired credential's challenge left pending,
     * from the chain only (never broadcast). Null when that challenge has no
     * claimed transaction of its own, so the credential is refused as expired.
     */
    private function reconcileExpired(Credential $credential, string $challengeId): ?string
    {
        $transaction = $credential->payload['transaction'] ?? null;
        if (!is_string($transaction) || $transaction === '') {
            return null;
        }
        try {
            [, $signature] = $this->signedTransaction($transaction);
        } catch (Throwable) {
            return null;
        }
        if (!$this->replayStore->has(self::PENDING_BINDING_PREFIX . $signature . ':' . $challengeId)) {
            return null;
        }
        return $this->reconcile($signature);
    }

    /**
     * Reconcile a signature another presentation already claimed, only when
     * it is this challenge's own pending charge. Any other claim (a payment
     * this or another SDK already settled on the shared ledger, or another
     * challenge's) is a replay: reconciling it would authorize a payment
     * that already authorized a response.
     */
    private function reconcileOwn(string $signature, string $challengeId): string
    {
        if (!$this->replayStore->has(self::PENDING_BINDING_PREFIX . $signature . ':' . $challengeId)) {
            throw new RuntimeException("Transaction signature already consumed: $signature");
        }
        return $this->reconcile($signature);
    }

    /**
     * Resolve a claimed signature from its on-chain status. Only an explicit
     * outcome resolves it: an execution error fails the charge, a confirmed
     * transaction authorizes one response, and anything else leaves the
     * charge pending.
     */
    private function reconcile(string $signature): string
    {
        if ($this->replayStore->has(self::REFUSED_PREFIX . $signature)) {
            throw new RuntimeException("Transaction $signature was refused and cannot settle");
        }
        if (SignatureConfirmation::isConfirmed($this->rpc, $signature, searchTransactionHistory: true)) {
            return $this->authorize($signature);
        }
        throw new SettlementInProgressException(
            "Transaction $signature is not confirmed yet; retry the same credential",
        );
    }

    /**
     * Record that `$signature` authorized this response. At most one request,
     * through any protocol, gets past this for one payment.
     */
    private function authorize(string $signature): string
    {
        if (!$this->consumedSignatures->authorize($signature)) {
            throw new RuntimeException("Transaction signature already consumed: $signature");
        }
        return $signature;
    }

    /**
     * Claim and authorize the signature in the ledger shared with x402, so a
     * payment settled through either protocol authorizes one request. Throws
     * on replay attempts.
     */
    private function consumeSignature(string $signature): void
    {
        if (!$this->consumedSignatures->claim($signature)) {
            throw new RuntimeException("Transaction signature already consumed: $signature");
        }
        $this->authorize($signature);
    }

    /** The base58 first signature of a serialized transaction: its id. */
    private static function firstSignature(string $wire): string
    {
        $count = 0;
        $offset = 0;
        for ($shift = 0; $offset < 3; $shift += 7) {
            if (!isset($wire[$offset])) {
                throw new InvalidArgumentException('invalid transaction payload');
            }
            $byte = ord($wire[$offset]);
            $offset += 1;
            $count |= ($byte & 0x7f) << $shift;
            if (($byte & 0x80) === 0) {
                break;
            }
        }
        if ($count < 1 || strlen($wire) < $offset + 64) {
            throw new InvalidArgumentException('transaction carries no signature');
        }
        return Base58::encode(substr($wire, $offset, 64));
    }

    /**
     * Whether a send error is a preflight rejection, the one send failure
     * that proves the node did not forward the transaction.
     */
    private static function isPreflightRejection(Throwable $error): bool
    {
        if (!$error instanceof RpcException || $error->getRpcErrorCode() !== -32002) {
            return false;
        }
        $data = $error->getRpcErrorData();
        return is_array($data) && array_key_exists('err', $data);
    }

    private function awaitConfirmation(string $signature): void
    {
        // Only a reported execution error fails the charge; an unreadable
        // or unconfirmed status keeps it pending so the retry reconciles it
        // instead of a fresh challenge releasing the client to pay again.
        SignatureConfirmation::await($this->rpc, $signature, $this->confirmationAttempts, $this->confirmationDelayMicros);
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
            $blockhash = TransactionWire::deserialize($wire)->recentBlockhash();
        } catch (Throwable) {
            return false;
        }
        return str_starts_with($blockhash, 'SURFNET');
    }
}
