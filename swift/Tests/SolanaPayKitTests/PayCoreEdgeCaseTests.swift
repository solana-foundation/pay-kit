import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - Ed25519 verify guard branches

@Suite("Ed25519 verify guards")
struct Ed25519VerifyGuardTests {
    @Test
    func rejectsWrongLengthSignature() {
        let publicKey = Data(repeating: 0x03, count: 32)
        #expect(throws: MppError.self) {
            _ = try Ed25519.verify(
                signature: Data(repeating: 0, count: 63), // not 64
                message: Data("m".utf8),
                publicKey: publicKey
            )
        }
    }

    @Test
    func rejectsWrongLengthPublicKey() {
        #expect(throws: MppError.self) {
            _ = try Ed25519.verify(
                signature: Data(repeating: 0, count: 64),
                message: Data("m".utf8),
                publicKey: Data(repeating: 0, count: 31) // not 32
            )
        }
    }
}

// MARK: - MemorySigner canned-signature initializer

@Suite("MemorySigner canned initializer")
struct MemorySignerCannedTests {
    @Test
    func signatureInitReturnsSameSignatureEveryCall() async throws {
        let publicKey = Data(repeating: 0xAA, count: 32)
        let cannedSig = Data(repeating: 0xBB, count: 64)
        let signer = MemorySigner(
            publicKey: publicKey,
            address: "canned-address",
            signature: cannedSig
        )
        #expect(signer.publicKey == publicKey)
        #expect(signer.address == "canned-address")
        let first = try await signer.sign(message: Data("one".utf8))
        let second = try await signer.sign(message: Data("two".utf8))
        #expect(first == cannedSig)
        #expect(second == cannedSig)
    }
}

// MARK: - x402 extensions builder

@Suite("buildX402Extensions")
struct BuildX402ExtensionsTests {
    /// No inbound extensions -> nil outbound (echo-and-omit).
    @Test
    func nilInboundYieldsNil() throws {
        #expect(try buildX402Extensions(echoing: nil) == nil)
    }

    /// Inbound extensions that do not require an identifier are echoed
    /// verbatim without adding an id.
    @Test
    func echoesWithoutIdentifierWhenNotRequired() throws {
        let inbound = JSONValue.object(["custom-ext": .object(["k": .string("v")])])
        let out = try buildX402Extensions(echoing: inbound)
        #expect(out != nil)
        #expect(out?.raw["custom-ext"] == .object(["k": .string("v")]))
        #expect(out?.paymentIdentifier == nil)
    }

    /// When the challenge requires a payment identifier, a pinned id is filled
    /// in without overwriting the server's `required` flag.
    @Test
    func fillsPinnedIdentifierWhenRequired() throws {
        let identifierExt = try JSONValue.encoding(
            X402PaymentIdentifierExtension(
                info: X402PaymentIdentifierInfo(required: true, id: nil)
            )
        )
        let inbound = JSONValue.object([X402PaymentIdentifierKey: identifierExt])
        let out = try buildX402Extensions(
            echoing: inbound,
            paymentIdentifierID: "pay_pinnedid0123456789abcd"
        )
        #expect(out?.paymentIdentifier?.info.id == "pay_pinnedid0123456789abcd")
        #expect(out?.paymentIdentifier?.info.required == true)
        #expect(out?.requiresPaymentIdentifier == true)
    }

    /// When required and no pinned id is passed, a fresh id is generated from
    /// the injected random bytes (deterministic in the test).
    @Test
    func generatesIdentifierWhenRequiredAndUnpinned() throws {
        let identifierExt = try JSONValue.encoding(
            X402PaymentIdentifierExtension(
                info: X402PaymentIdentifierInfo(required: true, id: nil)
            )
        )
        let inbound = JSONValue.object([X402PaymentIdentifierKey: identifierExt])
        let fixed = Data([
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ])
        let out = try buildX402Extensions(echoing: inbound, randomBytes: { fixed })
        #expect(out?.paymentIdentifier?.info.id == "pay_deadbeefcafebabe0102030405060708")
    }

    /// A non-object inbound extensions blob is a protocol error.
    @Test
    func throwsWhenInboundNotObject() {
        #expect(throws: MppError.self) {
            _ = try buildX402Extensions(echoing: .array([.int(1)]))
        }
    }
}

// MARK: - x402 payment builder edge cases

@Suite("x402 payment builder edge cases")
struct X402PaymentBuilderEdgeTests {
    static func makeSigner() throws -> MemorySigner {
        try MemorySigner(secretKey: Data(repeating: 0x01, count: 32))
    }

    static func makeRpc() -> RpcClient {
        RpcClient(endpoint: URL(string: "http://localhost:8899")!)
    }

    static let knownBlockhash = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"

    /// A memo longer than the 256-byte cap must be rejected.
    @Test
    func rejectsMemoOverCap() async throws {
        let bigMemo = String(repeating: "a", count: 257)
        let offer = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "5000", maxAmountRequired: nil, asset: "SOL",
            payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", recipient: nil,
            extra: [
                "recentBlockhash": .string(Self.knownBlockhash),
                "memo": .string(bigMemo),
            ]
        )
        await #expect(throws: MppError.self) {
            _ = try await buildX402PaymentHeader(
                signer: try Self.makeSigner(), rpc: Self.makeRpc(), offer: offer
            )
        }
    }

    /// A recentBlockhash that decodes to the wrong length is rejected.
    @Test
    func rejectsWrongLengthBlockhash() async throws {
        // Valid base58, but only 16 bytes.
        let shortBlockhash = Base58.encode(Data(repeating: 0x07, count: 16))
        let offer = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "5000", maxAmountRequired: nil, asset: "SOL",
            payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", recipient: nil,
            extra: ["recentBlockhash": .string(shortBlockhash)]
        )
        await #expect(throws: MppError.self) {
            _ = try await buildX402PaymentHeader(
                signer: try Self.makeSigner(), rpc: Self.makeRpc(), offer: offer
            )
        }
    }

    /// When the offer omits a blockhash, the builder falls back to the RPC.
    /// A stubbed RPC returns a known blockhash so the SOL transfer builds
    /// without a live network. Uses a dedicated URLProtocol (no shared static
    /// state) so it never races with the other transport suites.
    @Test
    func fallsBackToRpcBlockhashWhenOfferOmitsIt() async throws {
        let blockhash = Base58.encode(Data(repeating: 0x33, count: 32))
        RpcFallbackStubProtocol.blockhash = blockhash
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RpcFallbackStubProtocol.self]
        let session = URLSession(configuration: config)
        let rpc = RpcClient(endpoint: URL(string: "https://rpc.test/")!, urlSession: session)

        let offer = X402AcceptsEntry(
            scheme: "exact", network: SolanaNetwork.devnet,
            amount: "5000", maxAmountRequired: nil, asset: "SOL",
            payTo: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY", recipient: nil,
            extra: nil // no recentBlockhash -> RPC fallback
        )
        let header = try await buildX402PaymentHeader(
            signer: try Self.makeSigner(), rpc: rpc, offer: offer,
            nonceGenerator: { Data(repeating: 0xAB, count: 16) }
        )
        // The header decodes as a valid envelope with a non-empty transaction.
        let envData = Data(base64Encoded: header)!
        let env = try JSONDecoder().decode(X402PaymentSignatureEnvelope.self, from: envData)
        #expect(!env.payload.transaction.isEmpty)
    }
}

/// Dedicated URLProtocol for the RPC-blockhash-fallback test. Its only mutable
/// state is a single blockhash string set before use, so it does not race with
/// the shared `StubURLProtocol` / `X402StubURLProtocol` suites.
final class RpcFallbackStubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var blockhash = ""

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let body = try! JSONSerialization.data(
            withJSONObject: ["result": ["value": ["blockhash": Self.blockhash]]]
        )
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
