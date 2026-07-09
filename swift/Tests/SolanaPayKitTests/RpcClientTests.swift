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
        RPCClientURLProtocol.responder = { request in
            let body = try! JSONSerialization.jsonObject(with: request.httpBody!) as! [String: Any]
            switch body["method"] as? String {
            case "getLatestBlockhash":
                return RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":{"value":{"blockhash":"\#(blockhash)"}}}"#)
            case "getAccountInfo":
                return RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":{"value":{"owner":"TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}}}"#)
            default:
                return RPCClientResponse(statusCode: 500, body: "unexpected method")
            }
        }

        let rpc = client()
        let latest = try await rpc.getLatestBlockhash()
        #expect(latest.base58 == blockhash)
        #expect(latest.bytes == Data(repeating: 0x4A, count: 32))
        #expect(try await rpc.getAccountOwner(pubkeyBase58: "mint") == "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
    }

    @Test
    func sendsTransactionsAndSurfacesRPCFailures() async throws {
        RPCClientURLProtocol.reset()
        RPCClientURLProtocol.responder = { request in
            let body = try! JSONSerialization.jsonObject(with: request.httpBody!) as! [String: Any]
            let method = body["method"] as? String
            if method == "sendTransaction" {
                return RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"result":"signature"}"#)
            }
            return RPCClientResponse(body: #"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"denied"}}"#)
        }

        let rpc = client()
        #expect(try await rpc.sendTransaction("signed", skipPreflight: true) == "signature")
        await #expect(throws: PayKitError.rpcFailure("RPC error -32000: denied")) {
            _ = try await rpc.getAccountOwner(pubkeyBase58: "mint")
        }

        RPCClientURLProtocol.responder = { _ in RPCClientResponse(statusCode: 503, body: "unavailable") }
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
    nonisolated(unsafe) static var responder: ((URLRequest) -> RPCClientResponse)?

    static func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RPCClientURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    static func reset() {
        responder = nil
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let responder = Self.responder else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "rpc-client-test", code: 1))
            return
        }
        let fixture = responder(request)
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
