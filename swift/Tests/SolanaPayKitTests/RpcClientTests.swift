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
        RPCClientURLProtocol.responses = [
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"\#(blockhash)"}}}"#),
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":{"value":{"owner":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}}}"#),
        ]

        let rpc = client()
        let latest = try await rpc.getLatestBlockhash()
        #expect(latest.base58 == blockhash)
        #expect(latest.bytes == Data(repeating: 0x4A, count: 32))
        #expect(try await rpc.getAccountOwner(pubkeyBase58: "mint") == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    }

    @Test
    func sendsTransactionsAndSurfacesRPCFailures() async throws {
        RPCClientURLProtocol.reset()
        RPCClientURLProtocol.responses = [
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":"signature"}"#),
            RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}"#),
        ]

        let rpc = client()
        #expect(try await rpc.sendTransaction("signed", skipPreflight: true) == "signature")
        await #expect(throws: PayKitError.rpcFailure("RPC error -32000: denied")) {
            _ = try await rpc.getAccountOwner(pubkeyBase58: "mint")
        }

        RPCClientURLProtocol.responses = [RPCClientResponse(statusCode: 503, body: "unavailable")]
        await #expect(throws: PayKitError.rpcFailure("RPC HTTP 503")) {
            _ = try await rpc.sendTransaction("signed")
        }
    }
}

private struct RPCClientResponse {
    let statusCode: Int
    let body: String

    init(statusCode: Int = 200, body: String) {
        self.statusCode = statusCode
        self.body = body
    }
}

private final class RPCClientURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responses: [RPCClientResponse] = []

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RPCClientURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    static func reset() {
        responses = []
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard !Self.responses.isEmpty else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "rpc-client-test", code: 1))
            return
        }
        let fixture = Self.responses.removeFirst()
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
