import Foundation
// SwiftCrypto (`Crypto`) is API-compatible with Apple's CryptoKit for
// Curve25519 + SHA256 and ships on Linux, so the X402 client builds on
// ubuntu-latest CI as well as Apple platforms.
import Crypto

public protocol SolanaSigner {
    var address: SolanaPublicKey { get }
    func sign(message: Data) async throws -> Data
}

public struct MemorySolanaSigner: SolanaSigner {
    private let privateKey: Curve25519.Signing.PrivateKey
    public let address: SolanaPublicKey

    public init(secretKey: [UInt8]) throws {
        guard secretKey.count == 64 else {
            throw X402Error.invalidSecretKeyLength(secretKey.count)
        }
        let seed = Data(secretKey.prefix(32))
        let suppliedPublic = Data(secretKey.suffix(32))
        let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        // Derive the public key from the seed and verify the embedded suffix matches.
        // A mismatch indicates a malformed or tampered Solana keypair and we MUST
        // refuse to sign rather than signing with an attacker-controlled address.
        let derivedPublic = privateKey.publicKey.rawRepresentation
        guard derivedPublic == suppliedPublic else {
            let expected = try SolanaPublicKey(bytes: suppliedPublic).base58
            let derived = try SolanaPublicKey(bytes: derivedPublic).base58
            throw X402Error.publicKeyMismatch(expected: expected, derived: derived)
        }
        self.privateKey = privateKey
        self.address = try SolanaPublicKey(bytes: derivedPublic)
    }

    public func sign(message: Data) async throws -> Data {
        try privateKey.signature(for: message)
    }
}
