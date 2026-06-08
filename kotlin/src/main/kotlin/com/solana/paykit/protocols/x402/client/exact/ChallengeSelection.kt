package com.solana.paykit.protocols.x402.client.exact

/**
 * Client-side preferences for picking one offer from ``accepts``.
 *
 * Mirrors the rust ``ChallengeSelection`` and the Python ``ChallengeSelection``.
 */
data class ChallengeSelection(
    /** Solana network slug or CAIP-2 id. ``null`` defaults to mainnet
     *  (matching the rust spine + Python client). */
    val network: String? = null,
    /**
     * Priority-ordered currencies the client will pay in (symbols or mint
     * addresses). The first server offer matching the highest-priority
     * currency wins. ``null`` falls back to cheapest amount on the
     * preferred network.
     */
    val currencies: List<String>? = null,
)
