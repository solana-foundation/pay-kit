import Foundation
import CryptoKit

/// Application-owned Ed25519 signer abstraction.
///
/// The SDK never touches secret material directly. A `SolanaSigner`
/// implementation can sit in front of a remote signing service, a
/// hardware wallet, an iOS keychain entry, or (via `MemorySigner`) a
/// raw in-process keypair for tests and headless examples.
public protocol SolanaSigner: Sendable {
    var publicKey: Data { get }
    var address: String { get }

    func sign(message: Data) async throws -> Data
}

/// In-process signer for tests and headless examples.
///
/// Three initializers:
///
/// - `init(secretKey:)` accepts either a 32-byte Ed25519 seed or the
///   64-byte Solana canonical keypair file format (seed `||` public key).
///   Signing uses Apple CryptoKit `Curve25519.Signing.PrivateKey`, which
///   produces the deterministic 64-byte signature defined by RFC 8032.
/// - `init(publicKey:address:sign:)` accepts a custom signing closure for
///   tests that want to inject a canned response.
/// - `init(publicKey:address:signature:)` returns the same signature on
///   every call. Preserved from PR #83 for the credential-core tests.
public struct MemorySigner: SolanaSigner, Sendable {
    public let publicKey: Data
    public let address: String

    private let signHandler: @Sendable (Data) async throws -> Data

    public init(
        publicKey: Data,
        address: String,
        sign: @escaping @Sendable (Data) async throws -> Data
    ) {
        self.publicKey = publicKey
        self.address = address
        self.signHandler = sign
    }

    public init(publicKey: Data, address: String, signature: Data) {
        self.init(publicKey: publicKey, address: address) { _ in signature }
    }

    public init(secretKey: Data) throws {
        let privateKey = try Ed25519.privateKey(from: secretKey)
        let publicKey = privateKey.publicKey.rawRepresentation
        let address = Base58.encode(publicKey)
        self.publicKey = publicKey
        self.address = address
        let immutableKey = privateKey
        self.signHandler = { message in
            try Ed25519.sign(message: message, with: immutableKey)
        }
    }

    public func sign(message: Data) async throws -> Data {
        try await signHandler(message)
    }
}
