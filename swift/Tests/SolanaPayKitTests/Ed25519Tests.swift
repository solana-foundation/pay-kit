import Foundation
import Testing
import CryptoKit
@testable import SolanaPayKit

@Suite("Ed25519 via CryptoKit")
struct Ed25519Tests {
    @Test
    func signaturesAreFixedLengthAndAlwaysVerify() throws {
        // CryptoKit on macOS 26 / Swift 6.2 implements Ed25519 with the
        // randomized variant permitted by RFC 8032 section 5.1.6 (an
        // additional random nonce is mixed into the deterministic
        // hash-derived nonce). Solana validators check only that the
        // signature verifies, so we lock the property the wire actually
        // cares about: every signature is exactly 64 bytes and every
        // signature verifies under the matching public key.
        let seed = Data(repeating: 7, count: 32)
        let key = try Ed25519.privateKey(from: seed)
        let publicKey = key.publicKey.rawRepresentation
        let message = Data("Solana MPP charge".utf8)

        for _ in 0..<8 {
            let signature = try Ed25519.sign(message: message, with: key)
            #expect(signature.count == 64)
            #expect(try Ed25519.verify(signature: signature, message: message, publicKey: publicKey))
        }
    }

    @Test
    func acceptsSolanaCanonical64ByteKeypair() throws {
        // Seed `||` public key. CryptoKit derives the public key from the
        // seed, so we must build the canonical 64-byte form from a known
        // seed before parsing it back through `Ed25519.privateKey`.
        let seed = Data(repeating: 13, count: 32)
        let cryptoKitKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let publicKey = cryptoKitKey.publicKey.rawRepresentation
        let canonical = seed + publicKey

        let parsed = try Ed25519.privateKey(from: canonical)
        #expect(parsed.publicKey.rawRepresentation == publicKey)
    }

    @Test
    func rejectsBadSecretKeyLength() {
        #expect(throws: MppError.self) {
            _ = try Ed25519.privateKey(from: Data(repeating: 0, count: 31))
        }
    }

    @Test
    func verifiesSignaturesCorrectly() throws {
        let seed = Data(repeating: 19, count: 32)
        let key = try Ed25519.privateKey(from: seed)
        let publicKey = key.publicKey.rawRepresentation
        let message = Data("hello".utf8)
        let signature = try Ed25519.sign(message: message, with: key)

        #expect(try Ed25519.verify(signature: signature, message: message, publicKey: publicKey))

        let tampered = signature.prefix(63) + Data([signature.last! ^ 0xff])
        #expect(try !Ed25519.verify(signature: tampered, message: message, publicKey: publicKey))
    }

    @Test
    func canParseAsCryptoKitPublicKeyLengthCheck() {
        // CryptoKit accepts arbitrary 32-byte values as public keys, so
        // the only invariant we lock here is the length precondition.
        #expect(!Ed25519.canParseAsCryptoKitPublicKey(Data(repeating: 1, count: 16)))
        let seed = Data(repeating: 3, count: 32)
        let key = try! Ed25519.privateKey(from: seed)
        #expect(Ed25519.canParseAsCryptoKitPublicKey(key.publicKey.rawRepresentation))
    }

    @Test
    func memorySignerSignsViaCryptoKit() async throws {
        let seed = Data(repeating: 42, count: 32)
        let signer = try MemorySigner(secretKey: seed)
        let message = Data("payload".utf8)
        let signature = try await signer.sign(message: message)

        #expect(signature.count == 64)
        #expect(try Ed25519.verify(signature: signature, message: message, publicKey: signer.publicKey))
        // Address is base58 of the public key.
        #expect(signer.address == Base58.encode(signer.publicKey))
    }
}
