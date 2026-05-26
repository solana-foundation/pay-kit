package com.solana.mpp.crypto

import com.solana.mpp.protocol.MppException

import com.funkatronics.encoders.Base58 as MultimultBase58
import com.funkatronics.encoders.error.InvalidInputException

/**
 * Bitcoin-alphabet Base58 helpers used by Solana public keys, signatures, and
 * any other on-chain identifier that ships as a 32 or 64 byte value.
 *
 * Delegates to [com.funkatronics.encoders.Base58] from the Solana Mobile
 * `multimult` library, which is the same Base58 codec that `web3-solana`
 * and `mobile-wallet-adapter-clientlib` rely on. Keeping a thin wrapper
 * lets callers continue to use the [Base58.encode] / [Base58.decode]
 * signatures and lets us translate the upstream
 * [InvalidInputException.InvalidCharacter] into the SDK's typed
 * [MppException.InvalidBase58] for consistent error handling across the
 * Kotlin client.
 */
object Base58 {
    /** Encodes binary bytes as a Base58 string. */
    fun encode(binary: ByteArray): String = MultimultBase58.encodeToString(binary)

    /**
     * Decodes a Base58 string into binary bytes.
     *
     * Throws [MppException.InvalidBase58] for any character outside the
     * Bitcoin alphabet.
     */
    fun decode(value: String): ByteArray =
        try {
            MultimultBase58.decode(value)
        } catch (cause: InvalidInputException.InvalidCharacter) {
            throw MppException.InvalidBase58(cause.character)
        }
}
