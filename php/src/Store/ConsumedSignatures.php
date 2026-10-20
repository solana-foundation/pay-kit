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

    public function __construct(private readonly Store $store)
    {
    }

    /**
     * Atomically claim `$signature`. False means an earlier presentation,
     * through any protocol, already claimed it.
     */
    public function claim(string $signature): bool
    {
        return $this->store->putIfAbsent(self::KEY_PREFIX . $signature, true);
    }
}
