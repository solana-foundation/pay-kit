import Foundation
import Testing
@testable import SolanaPayKit

/// Exercises the `RpcClient` JSON-RPC methods against a dedicated URLProtocol
/// stub (`RpcClientStubProtocol`) so every parse branch and error path is
/// covered without a live network. Serialized because the stub keeps mutable
/// static state; a dedicated protocol class avoids racing with the other
/// transport suites that run in parallel.
@Suite("RpcClient JSON-RPC methods", .serialized)
struct RpcClientTests {
    private func makeClient(_ responder: @escaping (URLRequest) -> CoverageStubResponse) -> RpcClient {
        RpcClientStubProtocol.reset()
        RpcClientStubProtocol.responder = responder
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RpcClientStubProtocol.self]
        let session = URLSession(configuration: config)
        return RpcClient(endpoint: URL(string: "https://rpc.test/")!, urlSession: session)
    }

    private func json(_ object: [String: Any]) -> Data {
        try! JSONSerialization.data(withJSONObject: object)
    }

    // MARK: - getLatestBlockhash

    @Test
    func getLatestBlockhashReturnsBytesAndBase58() async throws {
        let blockhash = Base58.encode(Data(repeating: 0x11, count: 32))
        let client = makeClient { _ in
            CoverageStubResponse(
                statusCode: 200, headers: ["Content-Type": "application/json"],
                body: self.json(["result": ["value": ["blockhash": blockhash]]])
            )
        }
        let result = try await client.getLatestBlockhash()
        #expect(result.base58 == blockhash)
        #expect(result.bytes.count == 32)
        #expect(result.bytes == Data(repeating: 0x11, count: 32))
    }

    @Test
    func getLatestBlockhashThrowsOnMalformedBody() async {
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["result": ["value": [:]]]))
        }
        await #expect(throws: MppError.self) {
            _ = try await client.getLatestBlockhash()
        }
    }

    @Test
    func getLatestBlockhashThrowsWhenNot32Bytes() async {
        // A valid base58 string that decodes to fewer than 32 bytes.
        let shortHash = Base58.encode(Data(repeating: 0x22, count: 16))
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["result": ["value": ["blockhash": shortHash]]]))
        }
        await #expect(throws: MppError.self) {
            _ = try await client.getLatestBlockhash()
        }
    }

    // MARK: - getAccountOwner

    @Test
    func getAccountOwnerReturnsOwner() async throws {
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["result": ["value": ["owner": Mints.tokenProgram]]]))
        }
        let owner = try await client.getAccountOwner(pubkeyBase58: "SomePubkey1111111111111111111111111111111")
        #expect(owner == Mints.tokenProgram)
    }

    @Test
    func getAccountOwnerThrowsOnMissingValue() async {
        // `value` is null -> the `outer["value"] as? [String: Any]` guard fails.
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["result": ["value": NSNull()]]))
        }
        await #expect(throws: MppError.self) {
            _ = try await client.getAccountOwner(pubkeyBase58: "p")
        }
    }

    @Test
    func getAccountOwnerThrowsWhenNoOwnerField() async {
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["result": ["value": ["notOwner": "x"]]]))
        }
        await #expect(throws: MppError.self) {
            _ = try await client.getAccountOwner(pubkeyBase58: "p")
        }
    }

    // MARK: - sendTransaction

    @Test
    func sendTransactionReturnsSignature() async throws {
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["result": "SIG_ECHO_123"]))
        }
        let sig = try await client.sendTransaction("AQIDBA==", skipPreflight: true)
        #expect(sig == "SIG_ECHO_123")
    }

    @Test
    func sendTransactionThrowsOnNonStringResult() async {
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["result": 42]))
        }
        await #expect(throws: MppError.self) {
            _ = try await client.sendTransaction("AQID")
        }
    }

    // MARK: - rpcCall transport / protocol error paths

    @Test
    func throwsOnTransportError() async {
        // A transport error (thrown by the stub) surfaces from URLSession.data.
        RpcClientStubProtocol.reset()
        RpcClientStubProtocol.errorToThrow = NSError(domain: "test", code: -1)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [RpcClientStubProtocol.self]
        let session = URLSession(configuration: config)
        let client = RpcClient(endpoint: URL(string: "https://rpc.test/")!, urlSession: session)
        await #expect(throws: Error.self) {
            _ = try await client.sendTransaction("AQID")
        }
    }

    @Test
    func throwsOnNon2xxStatus() async {
        let client = makeClient { _ in
            CoverageStubResponse(statusCode: 500, headers: [:], body: Data())
        }
        await #expect(throws: MppError.self) {
            _ = try await client.sendTransaction("AQID")
        }
    }

    @Test
    func throwsWhenBodyNotObject() async {
        let client = makeClient { _ in
            // Valid JSON, but a top-level array, not an object.
            CoverageStubResponse(statusCode: 200, headers: [:], body: Data("[1,2,3]".utf8))
        }
        await #expect(throws: MppError.self) {
            _ = try await client.sendTransaction("AQID")
        }
    }

    @Test
    func throwsOnRpcErrorObject() async {
        let client = makeClient { _ in
            CoverageStubResponse(
                statusCode: 200, headers: [:],
                body: self.json(["error": ["code": -32000, "message": "Node is behind"]])
            )
        }
        await #expect(throws: MppError.self) {
            _ = try await client.sendTransaction("AQID")
        }
    }

    @Test
    func throwsWhenResultFieldMissing() async {
        let client = makeClient { _ in
            // No `error`, no `result`.
            CoverageStubResponse(statusCode: 200, headers: [:], body: self.json(["jsonrpc": "2.0", "id": 1]))
        }
        await #expect(throws: MppError.self) {
            _ = try await client.sendTransaction("AQID")
        }
    }
}
