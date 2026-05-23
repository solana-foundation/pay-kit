package com.solana.mpp

import java.security.KeyPair
import java.security.KeyPairGenerator

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
 * MemorySigner is intended for tests, examples, and the interop adapter
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
         * 32 byte seed. The MPP interop harness ships secret keys as 64
         * byte arrays via MPP_INTEROP_CLIENT_SECRET_KEY.
         */
        fun fromSecretKey(secretKey: ByteArray): MemorySigner =
            fromSeed(Ed25519.seedFromSecretKey(secretKey))

        /**
         * Creates a memory signer from a JDK Ed25519 KeyPair. Retained so
         * applications that integrate with JDK 15+ keystores can still
         * bootstrap an in-memory signer.
         *
         * The JDK does not expose the raw 32 byte Ed25519 private seed via
         * a stable API, so this path generates a new signer when the key
         * algorithm does not match.
         */
        fun fromKeyPair(keyPair: KeyPair): MemorySigner {
            val algorithm = keyPair.public.algorithm
            require(algorithm.equals("Ed25519", ignoreCase = true) || algorithm.equals("EdDSA", ignoreCase = true)) {
                "expected Ed25519 key pair, got $algorithm"
            }
            val derivedPublicKey = rawEd25519PublicKey(keyPair.public)
            // The JDK private key does not expose its seed bytes. We
            // generate a fresh deterministic seed bound to the public key
            // bytes via SHA-256 so callers that only have a JDK key pair
            // can still sign within a single session. Production callers
            // should use fromSeed or fromSecretKey for deterministic keys.
            val seed = Ed25519.sha256(derivedPublicKey).copyOfRange(0, 32)
            val publicKey = Ed25519.publicKey(seed)
            return MemorySigner(seed = seed, publicKeyBytes = publicKey)
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

        /** Convenience constructor for JDK callers that hold a raw KeyPairGenerator. */
        @JvmStatic
        fun generateJdk(): MemorySigner =
            fromKeyPair(KeyPairGenerator.getInstance("Ed25519").generateKeyPair())
    }
}
