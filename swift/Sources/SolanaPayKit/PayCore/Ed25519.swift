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
            throw PayKitError.signingFailure(
                "expected \(secretKeyLength) or \(solanaKeypairLength) byte secret, got \(raw.count)"
            )
        }

        do {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        } catch {
            throw PayKitError.signingFailure("CryptoKit rejected secret key: \(error)")
        }
    }

    public static func sign(message: Data, with privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        do {
            return try privateKey.signature(for: message)
        } catch {
            throw PayKitError.signingFailure("CryptoKit signature failed: \(error)")
        }
    }

    public static func verify(signature: Data, message: Data, publicKey: Data) throws -> Bool {
        guard signature.count == signatureLength else {
            throw PayKitError.signingFailure("signature must be \(signatureLength) bytes")
        }
        guard publicKey.count == publicKeyLength else {
            throw PayKitError.signingFailure("public key must be \(publicKeyLength) bytes")
        }
        do {
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            return key.isValidSignature(signature, for: message)
        } catch {
            throw PayKitError.signingFailure("CryptoKit rejected public key: \(error)")
        }
    }

    /// Returns true when the 32 bytes parse as a valid Ed25519 public
    /// key via `Curve25519.Signing.PublicKey(rawRepresentation:)`. This
    /// is **not** equivalent to the curve25519-dalek
    /// `CompressedEdwardsY::decompress` check Solana uses for PDA
    /// validation: Apple's initializer accepts arbitrary 32-byte values
    /// (including off-curve bytes and low-order points). For PDA work,
    /// use `Curve25519OnCurve.isOnCurve` (in `Curve25519Field.swift`)
    /// which implements the proper field arithmetic.
    ///
    /// Kept for callers that want the lenient CryptoKit behavior (e.g.
    /// passing through user-supplied public keys before delegating to
    /// CryptoKit verification, which would only fail at verify time).
    public static func canParseAsCryptoKitPublicKey(_ bytes: Data) -> Bool {
        guard bytes.count == publicKeyLength else { return false }
        return (try? Curve25519.Signing.PublicKey(rawRepresentation: bytes)) != nil
    }
}
