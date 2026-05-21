package com.solana.mpp

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

/** Signs Solana messages or transaction messages for MPP credential builders. */
interface SolanaSigner {
    /** Base64url-encoded raw 32-byte Ed25519 public key. */
    val publicKey: String

    /** Address alias used by wallet adapters that expose a Solana account string. */
    val address: String
        get() = publicKey

    /** Returns an Ed25519 signature for the provided message bytes. */
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
    /** Signs the provided message with this in-memory Ed25519 key pair. */
    override fun sign(message: ByteArray): ByteArray {
        val signature = Signature.getInstance(ED25519)
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }

    companion object {
        private const val ED25519 = "Ed25519"
        private val ED25519_X509_PREFIX = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )

        /** Generates a new in-memory Ed25519 signer for tests or local examples. */
        fun generate(): MemorySigner {
            val keyPair = KeyPairGenerator.getInstance(ED25519).generateKeyPair()
            return fromKeyPair(keyPair)
        }

        /** Creates a memory signer from a JDK Ed25519 key pair. */
        fun fromKeyPair(keyPair: KeyPair): MemorySigner =
            MemorySigner(
                privateKey = keyPair.private,
                publicKey = Base64Url.encode(rawEd25519PublicKey(keyPair.public)),
            )

        internal fun rawEd25519PublicKey(publicKey: PublicKey): ByteArray {
            val encoded = publicKey.encoded
            require(encoded.size == ED25519_X509_PREFIX.size + 32) { "expected Ed25519 X.509 public key" }
            require(encoded.copyOfRange(0, ED25519_X509_PREFIX.size).contentEquals(ED25519_X509_PREFIX)) {
                "expected Ed25519 X.509 public key"
            }
            return encoded.copyOfRange(ED25519_X509_PREFIX.size, encoded.size)
        }
    }
}
