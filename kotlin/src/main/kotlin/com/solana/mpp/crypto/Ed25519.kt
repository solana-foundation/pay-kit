package com.solana.mpp.crypto

import com.solana.mpp.protocol.MppException

import java.security.MessageDigest
import java.security.SecureRandom
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Ed25519 sign / verify wrapper backed by BouncyCastle.
 *
 * BouncyCastle is used (rather than the JDK 15+ EdDSA provider) so the
 * package can import a Solana keypair from its canonical raw seed format
 * directly. The JDK provider does not expose that path uniformly across
 * supported JVMs.
 *
 * Runtime dependency: org.bouncycastle:bcprov-jdk18on:1.78.1.
 */
object Ed25519 {
    private const val SEED_LENGTH = 32
    private const val SECRET_KEY_LENGTH = 64
    private const val PUBLIC_KEY_LENGTH = 32
    private const val SIGNATURE_LENGTH = 64

    /**
     * Signs `message` deterministically against the supplied 32 byte seed.
     *
     * Returns the canonical 64 byte Ed25519 signature.
     */
    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        require(seed.size == SEED_LENGTH) {
            "Ed25519 seed must be 32 bytes (got ${seed.size})"
        }
        val key = Ed25519PrivateKeyParameters(seed, 0)
        val signer = Ed25519Signer()
        signer.init(true, key)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /** Verifies a 64 byte Ed25519 signature against a 32 byte public key. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        require(publicKey.size == PUBLIC_KEY_LENGTH) {
            "Ed25519 public key must be 32 bytes (got ${publicKey.size})"
        }
        require(signature.size == SIGNATURE_LENGTH) {
            "Ed25519 signature must be 64 bytes (got ${signature.size})"
        }
        val key = Ed25519PublicKeyParameters(publicKey, 0)
        val verifier = Ed25519Signer()
        verifier.init(false, key)
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    /** Derives the 32 byte public key for a 32 byte seed. */
    fun publicKey(seed: ByteArray): ByteArray {
        require(seed.size == SEED_LENGTH) {
            "Ed25519 seed must be 32 bytes (got ${seed.size})"
        }
        return Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
    }

    /** Generates a fresh 32 byte seed using a secure random source. */
    fun generateSeed(): ByteArray {
        val random = SecureRandom()
        val seed = ByteArray(SEED_LENGTH)
        random.nextBytes(seed)
        return seed
    }

    /**
     * Normalises a raw secret-key input into a 32 byte seed.
     *
     * Solana's canonical keypair file ships 64 bytes (32 byte seed
     * concatenated with 32 byte public key). The MPP interop harness
     * passes `MPP_INTEROP_CLIENT_SECRET_KEY` as a JSON array of those 64
     * bytes. Some other tools ship the seed alone (32 bytes). This helper
     * accepts either.
     */
    fun seedFromSecretKey(secretKey: ByteArray): ByteArray = when (secretKey.size) {
        SEED_LENGTH -> secretKey.copyOf()
        SECRET_KEY_LENGTH -> secretKey.copyOfRange(0, SEED_LENGTH)
        else -> throw IllegalArgumentException(
            "Ed25519 secret key must be 32 or 64 bytes (got ${secretKey.size})",
        )
    }

    internal fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)
}

/** 32 byte Solana public key with base58 round-trip helpers. */
data class PublicKey(val bytes: ByteArray) {
    init {
        require(bytes.size == 32) { "Solana public key must be 32 bytes (got ${bytes.size})" }
    }

    /** Base58 encoded canonical form. */
    fun toBase58(): String = Base58.encode(bytes)

    override fun toString(): String = toBase58()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PublicKey) return false
        return bytes.contentEquals(other.bytes)
    }

    override fun hashCode(): Int = bytes.contentHashCode()

    companion object {
        /** Parses a base58 Solana address into a public key. */
        fun fromBase58(value: String): PublicKey {
            val decoded = try {
                Base58.decode(value)
            } catch (error: MppException.InvalidBase58) {
                throw MppException.InvalidPublicKey(value)
            }
            if (decoded.size != 32) {
                throw MppException.InvalidPublicKey(value)
            }
            return PublicKey(decoded)
        }
    }
}

/**
 * Solana program-derived address utilities.
 *
 * Matches `Pubkey::find_program_address` semantics used in the Rust spine
 * at `rust/src/client/charge.rs::get_associated_token_address`.
 */
object Pda {
    private val PDA_MARKER = "ProgramDerivedAddress".encodeToByteArray()
    private const val MAX_BUMP_SEED = 255

    /**
     * Finds a program-derived address by bump-iterating from 255 down to 0,
     * returning the first off-curve point (matches Solana SDK behaviour).
     */
    fun findProgramAddress(seeds: List<ByteArray>, programId: PublicKey): Pair<PublicKey, Int> {
        var bump = MAX_BUMP_SEED
        while (bump >= 0) {
            val candidateSeeds = seeds + byteArrayOf(bump.toByte())
            val candidate = try {
                createProgramAddress(candidateSeeds, programId)
            } catch (_: MppException.InvalidPublicKey) {
                bump -= 1
                continue
            }
            return candidate to bump
        }
        throw MppException.InvalidPublicKey("could not find a program-derived address")
    }

    /**
     * Hashes the seeds + program id + PDA marker to produce a candidate
     * program-derived address. Throws when the hash lands on the Ed25519
     * curve (a valid key); callers retry with a lower bump.
     */
    fun createProgramAddress(seeds: List<ByteArray>, programId: PublicKey): PublicKey {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        for (seed in seeds) {
            if (seed.size > 32) {
                throw MppException.InvalidPublicKey("seed exceeds 32 bytes")
            }
            digest.update(seed)
        }
        digest.update(programId.bytes)
        digest.update(PDA_MARKER)
        val hash = digest.digest()
        if (isOnCurve(hash)) {
            throw MppException.InvalidPublicKey("candidate is on curve")
        }
        return PublicKey(hash)
    }

    /**
     * Returns true when the supplied 32 bytes decompress to a valid point
     * on the Ed25519 curve. Matches Solana SDK's
     * `bytes_are_curve_point` / Pubkey::is_on_curve semantics.
     */
    internal fun isOnCurve(bytes: ByteArray): Boolean = OnCurveCheck.validate(bytes)

    /** Derives the Associated Token Account for `(owner, mint, tokenProgram)`. */
    fun associatedTokenAddress(
        owner: PublicKey,
        mint: PublicKey,
        tokenProgram: PublicKey,
    ): PublicKey {
        val ataProgram = PublicKey.fromBase58(Programs.ASSOCIATED_TOKEN_PROGRAM)
        val seeds = listOf(owner.bytes, tokenProgram.bytes, mint.bytes)
        return findProgramAddress(seeds, ataProgram).first
    }
}

/**
 * On-curve check used by program-derived address derivation.
 *
 * Implements the RFC 8032 §5.1.3 point-decoding test directly against
 * the Ed25519 field arithmetic. A 32 byte encoding decodes to a valid
 * (x, y) curve point iff `v * x^2 = u (mod p)` (or `v * x^2 = -u`)
 * has a solution for `x`, where `u = y^2 - 1`, `v = d * y^2 + 1`,
 * `p = 2^255 - 19`, and `d = -121665/121666 (mod p)`. Matches Solana
 * SDK's `Pubkey::is_on_curve` semantics.
 *
 * Implemented inline (rather than via the JDK 15+ EdECPublicKeySpec
 * round trip or a private BouncyCastle reflection hop) because:
 *
 * - JDK's KeyFactory.generatePublic does not actually enforce the
 *   on-curve check for EdECPublicKeySpec; arbitrary 32 byte y values
 *   round-trip cleanly without raising InvalidKeySpecException.
 * - The BouncyCastle private method that does enforce the check is
 *   gated by JDK 17+ strong encapsulation and breaks under
 *   `--illegal-access=deny` / module-system defaults.
 *
 * The math here is pure java.math.BigInteger, no JNI, no reflection.
 */
internal object OnCurveCheck {
    // RFC 8032 §5.1.3 constants.
    private val P = java.math.BigInteger.valueOf(2).pow(255)
        .subtract(java.math.BigInteger.valueOf(19))
    private val D = java.math.BigInteger("-121665")
        .multiply(java.math.BigInteger.valueOf(121666).modInverse(P))
        .mod(P)
    private val SQRT_MINUS_ONE = java.math.BigInteger.valueOf(2)
        .modPow(P.subtract(java.math.BigInteger.ONE).shiftRight(2), P)
    private val EXPONENT = P.subtract(java.math.BigInteger.valueOf(5)).shiftRight(3)

    fun validate(bytes: ByteArray): Boolean {
        if (bytes.size != 32) return false
        // RFC 8032 stores y little-endian with the sign of x in the high
        // bit of the last byte. Reverse to big-endian for BigInteger.
        val yLittle = bytes.copyOf()
        yLittle[31] = (yLittle[31].toInt() and 0x7f).toByte()
        val yBig = ByteArray(32)
        for (i in 0..31) yBig[i] = yLittle[31 - i]
        val y = java.math.BigInteger(1, yBig)
        if (y >= P) return false

        // Compute u = y^2 - 1, v = d * y^2 + 1 (mod p).
        val ySquared = y.multiply(y).mod(P)
        val u = ySquared.subtract(java.math.BigInteger.ONE).mod(P)
        val v = D.multiply(ySquared).add(java.math.BigInteger.ONE).mod(P)
        if (v == java.math.BigInteger.ZERO) return false

        // Candidate x = u * v^3 * (u * v^7)^((p-5)/8) per RFC 8032 §5.1.3.
        val vSquared = v.multiply(v).mod(P)
        val vCubed = vSquared.multiply(v).mod(P)
        val vSeventh = vCubed.multiply(vCubed).multiply(v).mod(P)
        val uvSeventh = u.multiply(vSeventh).mod(P)
        var x = u.multiply(vCubed).multiply(uvSeventh.modPow(EXPONENT, P)).mod(P)

        // Verify v * x^2 = +-u (mod p); pick the right root.
        val vxSquared = v.multiply(x.multiply(x).mod(P)).mod(P)
        if (vxSquared == u) {
            return true
        }
        val negU = P.subtract(u).mod(P)
        if (vxSquared == negU) {
            x = x.multiply(SQRT_MINUS_ONE).mod(P)
            val recheck = v.multiply(x.multiply(x).mod(P)).mod(P)
            return recheck == u
        }
        return false
    }
}
