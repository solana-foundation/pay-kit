package com.solana.mpp._paycore

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

    /**
     * Resolves a network slug or CAIP-2 identifier to its canonical CAIP-2 form.
     *
     * `null` defaults to devnet (matching the harness default
     * `X402_INTEROP_NETWORK` value and the rust spine default).
     * `localnet` shares the devnet CAIP-2 (Surfpool behaviour).
     */
    fun toCaip2(network: String?): String {
        if (network == null) return SOLANA_DEVNET
        val lowered = network.trim()
        if (lowered == SOLANA_MAINNET || lowered == SOLANA_DEVNET) return lowered
        return when (lowered) {
            "mainnet", "mainnet-beta", "solana" -> SOLANA_MAINNET
            "devnet", "solana-devnet", "localnet" -> SOLANA_DEVNET
            else -> SOLANA_DEVNET
        }
    }

    /** Returns `"devnet"` for the devnet CAIP-2, `"mainnet"` otherwise. */
    fun label(caip2: String): String = if (caip2 == SOLANA_DEVNET) "devnet" else "mainnet"
}
