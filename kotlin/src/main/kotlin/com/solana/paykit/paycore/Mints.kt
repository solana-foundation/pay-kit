package com.solana.paykit.paycore

/** Well-known Solana stablecoin mint addresses. */
object Mints {
    const val USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    const val USDC_DEVNET = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    const val USDT_MAINNET = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
    const val USDG_MAINNET = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
    const val USDG_DEVNET = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
    const val PYUSD_MAINNET = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
    const val PYUSD_DEVNET = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
    const val CASH_MAINNET = "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"
}

/**
 * Resolves a currency identifier (symbol or mint) to a mint address.
 * Returns null for native SOL.
 *
 * Mirrors `rust/src/protocol/solana.rs::resolve_stablecoin_mint`.
 */
fun resolveStablecoinMint(currency: String, network: String?): String? = when (currency.uppercase()) {
    "SOL" -> null
    "USDC" -> when (network) {
        "devnet" -> Mints.USDC_DEVNET
        "testnet" -> Mints.USDC_DEVNET
        else -> Mints.USDC_MAINNET
    }
    "USDT" -> Mints.USDT_MAINNET
    "USDG" -> when (network) {
        "devnet" -> Mints.USDG_DEVNET
        "testnet" -> Mints.USDG_DEVNET
        else -> Mints.USDG_MAINNET
    }
    "PYUSD" -> when (network) {
        "devnet" -> Mints.PYUSD_DEVNET
        "testnet" -> Mints.PYUSD_DEVNET
        else -> Mints.PYUSD_MAINNET
    }
    "CASH" -> Mints.CASH_MAINNET
    else -> currency
}

/**
 * Reverse lookup: a currency symbol or mint address to its canonical symbol,
 * or null for native SOL / unknown values. Mirrors rust `stablecoin_symbol`.
 */
fun stablecoinSymbol(currencyOrMint: String): String? = when (currencyOrMint.uppercase()) {
    "SOL" -> null
    "USDC" -> "USDC"
    "USDT" -> "USDT"
    "USDG" -> "USDG"
    "PYUSD" -> "PYUSD"
    "CASH" -> "CASH"
    else -> when (currencyOrMint) {
        Mints.USDC_MAINNET, Mints.USDC_DEVNET -> "USDC"
        Mints.USDT_MAINNET -> "USDT"
        Mints.USDG_MAINNET, Mints.USDG_DEVNET -> "USDG"
        Mints.PYUSD_MAINNET, Mints.PYUSD_DEVNET -> "PYUSD"
        Mints.CASH_MAINNET -> "CASH"
        else -> null
    }
}

/** True if a stablecoin (by symbol or mint) settles on SPL Token-2022. */
fun stablecoinUsesToken2022(currencyOrMint: String): Boolean =
    stablecoinSymbol(currencyOrMint) in setOf("USDG", "PYUSD", "CASH")

/**
 * Default token program for a currency or mint, resolving the mint first so
 * symbols and addresses agree. Mirrors rust `default_token_program_for_currency`:
 * Token-2022 mints (USDG, PYUSD, CASH) use the Token-2022 program; everything
 * else the legacy Token program.
 */
fun defaultTokenProgramForCurrency(currency: String, network: String?): String {
    val mint = resolveStablecoinMint(currency, network) ?: currency
    return if (stablecoinUsesToken2022(mint)) Programs.TOKEN_2022_PROGRAM else Programs.TOKEN_PROGRAM
}
