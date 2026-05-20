package com.solana.mpp

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature

interface SolanaSigner {
    val publicKey: String
    val address: String
        get() = publicKey

    fun sign(message: ByteArray): ByteArray
}

/**
 * In-memory Ed25519 signer for tests and local development.
 *
 * Production Solana wallet integrations should provide their own SolanaSigner
 * backed by a wallet, keychain, HSM, or mobile signing adapter.
 */
class MemorySigner private constructor(
    private val privateKey: PrivateKey,
    override val publicKey: String,
) : SolanaSigner {
    override fun sign(message: ByteArray): ByteArray {
        val signature = Signature.getInstance(ED25519)
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }

    companion object {
        private const val ED25519 = "Ed25519"

        fun generate(): MemorySigner {
            val keyPair = KeyPairGenerator.getInstance(ED25519).generateKeyPair()
            return fromKeyPair(keyPair)
        }

        fun fromKeyPair(keyPair: KeyPair): MemorySigner =
            MemorySigner(
                privateKey = keyPair.private,
                publicKey = Base64Url.encode(keyPair.public.encoded),
            )
    }
}
