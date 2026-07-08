package com.solana.paykit.paycore

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * A typed CAIP-2 Solana network identifier.
 *
 * Wire-compatible with the plain string the protocols carry: it serializes to
 * exactly its CAIP-2 id and deserializes any string back, mapping the known
 * clusters to their cases and preserving everything else verbatim in [Other]
 * so an unknown network never fails to parse. The raw id constants and
 * slug resolution live in [Network].
 */
@Serializable(with = SolanaNetworkSerializer::class)
sealed class SolanaNetwork {
    /** The CAIP-2 identifier this network serializes to. */
    abstract val caip2: String

    /** Solana mainnet-beta. */
    object Mainnet : SolanaNetwork() {
        override val caip2: String get() = Network.SOLANA_MAINNET
    }

    /** Solana devnet (and Surfpool localnet, which shares the devnet id). */
    object Devnet : SolanaNetwork() {
        override val caip2: String get() = Network.SOLANA_DEVNET
    }

    /** Solana testnet. */
    object Testnet : SolanaNetwork() {
        override val caip2: String get() = Network.SOLANA_TESTNET
    }

    /** A CAIP-2 network this SDK does not special-case, preserved verbatim. */
    data class Other(override val caip2: String) : SolanaNetwork()

    companion object {
        /** Maps a CAIP-2 id to its typed case ([Other] when unrecognized). */
        fun fromCaip2(caip2: String): SolanaNetwork = when (caip2) {
            Network.SOLANA_MAINNET -> Mainnet
            Network.SOLANA_DEVNET -> Devnet
            Network.SOLANA_TESTNET -> Testnet
            else -> Other(caip2)
        }
    }
}

/** Serializes a [SolanaNetwork] as its bare CAIP-2 string (no wrapper object). */
object SolanaNetworkSerializer : KSerializer<SolanaNetwork> {
    /** A plain string on the wire. */
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("SolanaNetwork", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: SolanaNetwork) {
        encoder.encodeString(value.caip2)
    }

    override fun deserialize(decoder: Decoder): SolanaNetwork =
        SolanaNetwork.fromCaip2(decoder.decodeString())
}
