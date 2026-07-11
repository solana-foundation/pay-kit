import Foundation
import Testing
@testable import SolanaPayKit

@Suite("RPC client", .serialized)
struct RpcClientTests {
    private func client() -> RpcClient {
        RpcClient(endpoint: URL(string: "https://rpc.stub.test")!, urlSession: RPCClientURLProtocol.session())
    }

    @Test
    func fetchesConfirmedBlockhashAndAccountOwner() async throws {
        let blockhash = Base58.encode(Data(repeating: 0x4A, count: 32))
        RPCClientURLProtocol.reset()
        RPCClientURLProtocol.install([
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"\#(blockhash)"}}}"#),
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":{"value":{"owner":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}}}"#),
        ])

        let rpc = client()
        let latest = try await rpc.getLatestBlockhash()
        #expect(latest.base58 == blockhash)
        #expect(latest.bytes == Data(repeating: 0x4A, count: 32))
        #expect(try await rpc.getAccountOwner(pubkeyBase58: "mint") == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    }

    @Test
    func sendsTransactionsAndSurfacesRPCFailures() async throws {
        RPCClientURLProtocol.reset()
        RPCClientURLProtocol.install([
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":"signature"}"#),
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}"#),
        ])

        let rpc = client()
        #expect(try await rpc.sendTransaction("signed", skipPreflight: true) == "signature")
        await #expect(throws: PayKitError.rpcFailure("RPC error -32000: denied")) {
            _ = try await rpc.getAccountOwner(pubkeyBase58: "mint")
        }

        RPCClientURLProtocol.install([RPCClientResponse(statusCode: 503, body: "unavailable")])
        await #expect(throws: PayKitError.rpcFailure("RPC HTTP 503")) {
            _ = try await rpc.sendTransaction("signed")
        }
    }

    @Test
    func safelyConsumesConcurrentFixtureResponses() async throws {
        let owner = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        let fixture = RPCClientResponse(
            body: #"{"jsonrpc":"2.0","id":1,"result":{"value":{"owner":"\#(owner)"}}}"#
        )
        RPCClientURLProtocol.install(Array(repeating: fixture, count: 32))

        let rpc = client()
        try await withThrowingTaskGroup(of: String.self) { group in
            for index in 0..<32 {
                group.addTask {
                    try await rpc.getAccountOwner(pubkeyBase58: "mint-\(index)")
                }
            }
            for try await actualOwner in group {
                #expect(actualOwner == owner)
            }
        }
    }
}

private struct RPCClientResponse: Sendable {
    let statusCode: Int
    let body: String

    init(statusCode: Int = 200, body: String) {
        self.statusCode = statusCode
        self.body = body
    }
}

private final class RPCClientFixtureStore: @unchecked Sendable {
    private let lock = NSLock()
    private var responses: [RPCClientResponse] = []

    func install(_ responses: [RPCClientResponse]) {
        lock.lock()
        defer { lock.unlock() }
        self.responses = responses
    }

    func next() -> RPCClientResponse? {
        lock.lock()
        defer { lock.unlock() }
        guard !responses.isEmpty else { return nil }
        return responses.removeFirst()
    }
}

private final class RPCClientURLProtocol: URLProtocol, @unchecked Sendable {
    private static let fixtures = RPCClientFixtureStore()

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RPCClientURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    static func reset() {
        fixtures.install([])
    }

    static func install(_ responses: [RPCClientResponse]) {
        fixtures.install(responses)
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let fixture = Self.fixtures.next() else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "rpc-client-test", code: 1))
            return
        }
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: fixture.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(fixture.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
