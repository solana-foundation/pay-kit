<?php

declare(strict_types=1);

namespace PayKit\Store;

/**
 * Protocol-independent ledger of Solana transaction signatures that already
 * authorized a protected response.
 *
 * MPP charge and x402 `exact` both claim here, so one on-chain payment
 * authorizes one request whichever protocol presents it: a transaction
 * settled through MPP cannot be presented again as an x402 payment on a gate
 * that shares the store, and vice versa. The key is the signature alone (a
 * signature commits to a cluster-specific blockhash, so a network scope adds
 * nothing) and matches the other pay-kit SDKs, so mixed-language replicas on
 * one shared store agree.
 */
final class ConsumedSignatures
{
    private const KEY_PREFIX = 'solana:consumed-signature:';
    private const AUTHORIZED_KEY_PREFIX = 'solana:authorized-signature:';
    /**
     * Keys under which MPP charge and x402 `exact` claimed signatures before
     * they shared this ledger. Every claim also takes them, so that during a
     * rolling upgrade a replica still running the previous release (which
     * claims and checks only its own legacy key) sees a payment this release
     * accepted, and the other way round.
     */
    private const LEGACY_KEY_PREFIXES = ['solana-charge:consumed:', 'x402-svm-exact:consumed:'];

    public function __construct(private readonly Store $store)
    {
    }

    /**
     * Atomically claim `$signature`. False means an earlier presentation,
     * through any protocol or release, already claimed it.
     *
     * The legacy keys come first, each taken with `putIfAbsent`, so a replica
     * on the previous release, which claims its own legacy key the same way,
     * contends on the very same key: at most one of them wins, with no window
     * between a check and a write. A signature already held under any of them
     * stays consumed and is never migrated. The store cannot delete, so a
     * refused claim keeps the legacy keys it took; that only fails closed, for
     * a signature someone else already holds.
     */
    public function claim(string $signature): bool
    {
        foreach (self::LEGACY_KEY_PREFIXES as $prefix) {
            if (!$this->store->putIfAbsent($prefix . $signature, true)) {
                return false;
            }
        }
        return $this->store->putIfAbsent(self::KEY_PREFIX . $signature, true);
    }

    /**
     * Atomically record that `$signature`, already claimed, authorized a
     * protected response. False means another request, through any protocol,
     * was already authorized by it.
     *
     * Claiming and authorizing are separate steps so a claimed payment whose
     * outcome is not known yet (a lost broadcast response, an unconfirmed
     * transaction) stays pending: a retry reconciles it against the chain and
     * authorizes it once it lands, while a replay of a payment that already
     * authorized a response is refused.
     */
    public function authorize(string $signature): bool
    {
        // Only a ledger claim can be authorized. A signature held under a
        // legacy key alone (a pre-ledger claim, or a previous release's)
        // stays consumed: it is never reconciled into an authorization.
        if (!$this->store->has(self::KEY_PREFIX . $signature)) {
            return false;
        }
        return $this->store->putIfAbsent(self::AUTHORIZED_KEY_PREFIX . $signature, true);
    }
}
