package com.solana.paykit.paycore

import java.security.KeyPair

/** Signs Solana messages or transaction messages for MPP credential builders. */
interface SolanaSigner {
    /** Raw 32 byte Ed25519 public key. */
    val publicKeyBytes: ByteArray

    /** Base58 Solana address (canonical 32 byte public key in base58). */
    val address: String
        get() = Base58.encode(publicKeyBytes)

    /** Base64url-encoded raw 32 byte Ed25519 public key. */
    val publicKey: String
        get() = Base64Url.encode(publicKeyBytes)

    /** Returns an Ed25519 signature for the provided message bytes. */
    fun sign(message: ByteArray): ByteArray
}

/**
 * In-memory Ed25519 signer backed by BouncyCastle.
 *
 * Production wallet integrations should provide their own SolanaSigner.
 * MemorySigner is intended for tests, examples, and the harness adapter
 * where the harness ships secret keys as raw byte arrays.
 */
class MemorySigner private constructor(
    private val seed: ByteArray,
    override val publicKeyBytes: ByteArray,
) : SolanaSigner {
    override fun sign(message: ByteArray): ByteArray = Ed25519.sign(seed, message)

    /** Returns the 32 byte Ed25519 seed (private key). For test or harness use only. */
    fun seedBytes(): ByteArray = seed.copyOf()

    companion object {
        private val ED25519_X509_PREFIX = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )

        /** Generates a new in-memory Ed25519 signer for tests or local examples. */
        fun generate(): MemorySigner = fromSeed(Ed25519.generateSeed())

        /** Creates a memory signer from a 32 byte Ed25519 seed. */
        fun fromSeed(seed: ByteArray): MemorySigner {
            require(seed.size == 32) { "seed must be 32 bytes (got ${seed.size})" }
            val seedCopy = seed.copyOf()
            val publicKey = Ed25519.publicKey(seedCopy)
            return MemorySigner(seed = seedCopy, publicKeyBytes = publicKey)
        }

        /**
         * Accepts the Solana canonical 64 byte secret-key format or a raw
         * 32 byte seed. The MPP harness ships secret keys as 64
         * byte arrays via MPP_HARNESS_CLIENT_SECRET_KEY.
         */
        fun fromSecretKey(secretKey: ByteArray): MemorySigner =
            fromSeed(Ed25519.seedFromSecretKey(secretKey))

        /**
         * Rejects JDK Ed25519 KeyPair-only inputs.
         *
         * The JDK does not expose the raw 32 byte Ed25519 seed via a
         * stable API. Building a MemorySigner from a JDK KeyPair alone
         * would produce a signer whose public key does not match the
         * caller's key pair, so any transaction signed through it would
         * advertise (and spend from) the wrong account. Callers that hold
         * a JDK KeyPair should instead use fromSeed or fromSecretKey
         * with the raw key material, or implement SolanaSigner directly
         * against their wallet / keystore signing primitive.
         */
        fun fromKeyPair(keyPair: KeyPair): MemorySigner {
            val algorithm = keyPair.public.algorithm
            require(algorithm.equals("Ed25519", ignoreCase = true) || algorithm.equals("EdDSA", ignoreCase = true)) {
                "expected Ed25519 key pair, got $algorithm"
            }
            // Validate the public key shape so legacy callers still get
            // the same precondition errors they had before.
            rawEd25519PublicKey(keyPair.public)
            throw IllegalArgumentException(
                "MemorySigner.fromKeyPair cannot recover the Ed25519 seed from a JDK PrivateKey. " +
                    "Use MemorySigner.fromSeed(seed) or MemorySigner.fromSecretKey(secretKey) with " +
                    "the raw key bytes, or implement SolanaSigner against your wallet's signing API.",
            )
        }

        /**
         * Extracts the raw 32 byte Ed25519 public key from a JDK encoded
         * X.509 SubjectPublicKeyInfo wrapper.
         */
        fun rawEd25519PublicKey(publicKey: java.security.PublicKey): ByteArray {
            val encoded = publicKey.encoded
            require(encoded.size == ED25519_X509_PREFIX.size + 32) {
                "expected Ed25519 X.509 public key"
            }
            require(encoded.copyOfRange(0, ED25519_X509_PREFIX.size).contentEquals(ED25519_X509_PREFIX)) {
                "expected Ed25519 X.509 public key"
            }
            return encoded.copyOfRange(ED25519_X509_PREFIX.size, encoded.size)
        }

    }
}
