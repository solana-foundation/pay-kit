import Foundation
import CryptoKit

/// Ed25519 signing and verification via Apple CryptoKit.
///
/// Apple `Curve25519.Signing` implements the randomized variant
/// permitted by RFC 8032 section 5.1.6: signing the same message twice
/// with the same secret key returns two different 64-byte signatures
/// that both verify. Solana validators check only that the signature
/// verifies under the corresponding public key, so randomized output is
/// wire-compatible. The Rust and TypeScript spines use deterministic
/// `ed25519-dalek` / `@solana/keys`; both shapes are interchangeable on
/// the network because Ed25519 verification accepts any valid signature.
public enum Ed25519 {
    public static let secretKeyLength = 32
    public static let solanaKeypairLength = 64
    public static let publicKeyLength = 32
    public static let signatureLength = 64

    /// Builds a CryptoKit private key from either a 32-byte seed or the
    /// 64-byte Solana canonical keypair file format (seed `||` public key).
    public static func privateKey(from raw: Data) throws -> Curve25519.Signing.PrivateKey {
        let seed: Data
        switch raw.count {
        case secretKeyLength:
            seed = raw
        case solanaKeypairLength:
            seed = raw.prefix(secretKeyLength)
        default:
            throw MppError.signingFailure(
                "expected \(secretKeyLength) or \(solanaKeypairLength) byte secret, got \(raw.count)"
            )
        }

        do {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        } catch {
            throw MppError.signingFailure("CryptoKit rejected secret key: \(error)")
        }
    }

    public static func sign(message: Data, with privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        do {
            return try privateKey.signature(for: message)
        } catch {
            throw MppError.signingFailure("CryptoKit signature failed: \(error)")
        }
    }

    public static func verify(signature: Data, message: Data, publicKey: Data) throws -> Bool {
        guard signature.count == signatureLength else {
            throw MppError.signingFailure("signature must be \(signatureLength) bytes")
        }
        guard publicKey.count == publicKeyLength else {
            throw MppError.signingFailure("public key must be \(publicKeyLength) bytes")
        }
        do {
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            return key.isValidSignature(signature, for: message)
        } catch {
            throw MppError.signingFailure("CryptoKit rejected public key: \(error)")
        }
    }

    /// Returns true when the 32 bytes can be parsed as a valid Ed25519
    /// public key (i.e. lie on the curve). Used by ATA PDA derivation to
    /// reject candidate seeds whose hash lands on the curve.
    public static func isOnCurve(_ bytes: Data) -> Bool {
        guard bytes.count == publicKeyLength else { return false }
        return (try? Curve25519.Signing.PublicKey(rawRepresentation: bytes)) != nil
    }
}
