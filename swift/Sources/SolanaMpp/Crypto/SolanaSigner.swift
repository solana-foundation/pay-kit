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
///   Signing uses Apple CryptoKit `Curve25519.Signing.PrivateKey`. The
///   Ed25519 signature scheme itself is deterministic per RFC 8032 sec 5.1.6
///   for any given (private key, message) pair, but Apple CryptoKit's
///   public-API contract on `signature(for:)` does not guarantee
///   determinism across iOS / macOS releases (it may add a random nonce
///   for side-channel hardening in a future version). Callers that need a
///   hard guarantee of bit-for-bit reproducibility across runtimes should
///   inject their own RFC 8032 implementation via the `sign:` closure
///   initializer below.
/// - `init(publicKey:address:sign:)` accepts a custom signing closure for
///   tests that want to inject a canned response.
/// - `init(publicKey:address:signature:)` returns the same signature on
///   every call. Preserved from PR #83 for the credential-core tests.
public struct MemorySigner: SolanaSigner, Sendable {
    public let publicKey: Data
    public let address: String

    private let signHandler: @Sendable (Data) async throws -> Data

    /// Custom-handler initializer. **Trust boundary**: this initializer
    /// accepts a caller-supplied `publicKey` and `address` and does not
    /// verify that the supplied `sign` closure actually controls the
    /// corresponding secret. The SDK does not check signatures against
    /// the embedded public key; that pairing is the caller's
    /// responsibility (for production code, prefer `init(secretKey:)`
    /// or wire `sign` to a hardware / remote signer whose public key
    /// you trust out-of-band). Misuse here yields credentials the
    /// MPP server will reject at HMAC + chain-verification time, not a
    /// silent forgery, but the failure mode is "credential rejected
    /// after RPC round-trip" rather than "rejected locally".
    public init(
        publicKey: Data,
        address: String,
        sign: @escaping @Sendable (Data) async throws -> Data
    ) {
        self.publicKey = publicKey
        self.address = address
        self.signHandler = sign
    }

    /// Test-only initializer. Returns the same canned signature on
    /// every call. Same trust caveat as `init(publicKey:address:sign:)`.
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
