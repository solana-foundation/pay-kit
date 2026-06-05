package com.solana.paykit.paycore

/**
 * CAIP-2 network identifiers and slug-to-CAIP-2 resolution for Solana.
 *
 * The x402 exact protocol uses CAIP-2 identifiers on the wire (e.g.
 * `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1` for devnet). Harness env vars
 * and user-facing APIs also accept friendly slugs (mainnet, devnet,
 * localnet). This helper normalises both forms to the canonical CAIP-2 id.
 */
object Network {
    /** CAIP-2 id for Solana mainnet-beta. */
    const val SOLANA_MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

    /**
     * CAIP-2 id for Solana devnet (and Surfpool localnet, which forks
     * mainnet state under the devnet genesis hash).
     */
    const val SOLANA_DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"

    /** CAIP-2 id for Solana testnet. */
    const val SOLANA_TESTNET = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"

    /**
     * Resolves a network slug or CAIP-2 identifier to its canonical CAIP-2 form.
     *
     * `null` defaults to mainnet, matching the rust spine
     * (`select_requirement` uses `.unwrap_or(SOLANA_MAINNET)`) and the
     * Python client default. `localnet` shares the devnet CAIP-2 (Surfpool
     * behaviour). Callers that want devnet (e.g. the interop harness) pass an
     * explicit network slug or CAIP-2 id.
     */
    fun toCaip2(network: String?): String {
        if (network == null) return SOLANA_MAINNET
        val slug = network.trim()
        if (slug == SOLANA_MAINNET || slug == SOLANA_DEVNET || slug == SOLANA_TESTNET) {
            return slug
        }
        return when (slug) {
            "mainnet", "mainnet-beta", "solana" -> SOLANA_MAINNET
            "devnet", "solana-devnet", "localnet" -> SOLANA_DEVNET
            "testnet", "solana-testnet" -> SOLANA_TESTNET
            // Unknown slugs resolve to mainnet, matching the rust
            // `caip2_network_for_cluster` catch-all (`_ => SOLANA_MAINNET`).
            else -> SOLANA_MAINNET
        }
    }

    /** Maps a CAIP-2 id to its cluster label (`devnet` / `testnet` / `mainnet`). */
    fun label(caip2: String): String = when (caip2) {
        SOLANA_DEVNET -> "devnet"
        SOLANA_TESTNET -> "testnet"
        else -> "mainnet"
    }
}
