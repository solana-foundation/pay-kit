import Foundation
import Testing
@testable import SolanaMpp

@Suite("MppHTTPClient 402 retry semantics", .serialized)
struct HTTPClientTests {
    @Test
    func splitsCommaJoinedWWWAuthenticatePerChallenge() {
        let req = Base64URL.encode(Data(#"{"amount":"1","currency":"SOL","recipient":"11111111111111111111111111111112","methodDetails":{}}"#.utf8))
        let combined = """
        Payment id="a", realm="MPP Payment", method="solana", intent="charge", request="\(req)", Payment id="b", realm="MPP Payment", method="solana", intent="charge", request="\(req)"
        """
        let parts = MppHTTPClient.splitWWWAuthenticate(combined)
        #expect(parts.count == 2)
        #expect(parts[0].contains("id=\"a\""))
        #expect(parts[1].contains("id=\"b\""))
    }

    @Test
    func retriesOnceOn402AndReturnsReplayResponse() async throws {
        StubURLProtocol.reset()
        let blockhash = Base58.encode(Data(repeating: 0x44, count: 32))
        let requestJson = """
        {
          "amount": "1000",
          "currency": "SOL",
          "recipient": "5wEwLBR3aTGdz8wWUFKafdGiLcQNqotQK1ndJxXLfHir",
          "methodDetails": {
            "network": "localnet",
            "recentBlockhash": "\(blockhash)"
          }
        }
        """
        let requestB64 = Base64URL.encode(Data(requestJson.utf8))
        let challengeHeader = """
        Payment id="ch-1", realm="MPP Payment", method="solana", intent="charge", request="\(requestB64)"
        """

        let url = URL(string: "https://example.test/protected")!

        StubURLProtocol.responder = { req in
            if req.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Payment ") == true {
                let headers = [
                    "Content-Type": "application/json",
                    "x-fixture-settlement": "SETTLEMENT_SIG_XXX",
                ]
                return StubResponse(statusCode: 200, headers: headers, body: Data(#"{"ok":true}"#.utf8))
            }
            return StubResponse(
                statusCode: 402,
                headers: ["WWW-Authenticate": challengeHeader],
                body: Data()
            )
        }

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)
        let signer = try MemorySigner(secretKey: Data(repeating: 1, count: 32))
        let client = MppHTTPClient(signer: signer, urlSession: session)

        let response = try await client.fetch(url: url)
        #expect(response.status == 200)
        #expect(response.settlementSignature == "SETTLEMENT_SIG_XXX")
        #expect(String(decoding: response.body, as: UTF8.self) == "{\"ok\":true}")
        #expect(StubURLProtocol.requestCount == 2)
    }

    @Test
    func doesNotRetryOnNon402Status() async throws {
        StubURLProtocol.reset()
        StubURLProtocol.responder = { _ in
            StubResponse(statusCode: 500, headers: [:], body: Data())
        }
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)
        let signer = try MemorySigner(secretKey: Data(repeating: 2, count: 32))
        let client = MppHTTPClient(signer: signer, urlSession: session)

        let response = try await client.fetch(url: URL(string: "https://example.test/x")!)
        #expect(response.status == 500)
        #expect(StubURLProtocol.requestCount == 1)
    }

    @Test
    func doesNotRetryOnTransportError() async throws {
        StubURLProtocol.reset()
        StubURLProtocol.errorToThrow = NSError(domain: "test", code: -1, userInfo: nil)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: config)
        let signer = try MemorySigner(secretKey: Data(repeating: 3, count: 32))
        let client = MppHTTPClient(signer: signer, urlSession: session)

        do {
            _ = try await client.fetch(url: URL(string: "https://example.test/x")!)
            Issue.record("expected transport error to propagate")
        } catch {
            // Expected
        }
        #expect(StubURLProtocol.requestCount == 1)
    }
}

// MARK: - URLProtocol stub

struct StubResponse {
    let statusCode: Int
    let headers: [String: String]
    let body: Data
}

final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responder: ((URLRequest) -> StubResponse)?
    nonisolated(unsafe) static var errorToThrow: Error?
    nonisolated(unsafe) static var requestCount = 0

    static func reset() {
        responder = nil
        errorToThrow = nil
        requestCount = 0
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requestCount += 1
        if let err = Self.errorToThrow {
            client?.urlProtocol(self, didFailWithError: err)
            return
        }
        guard let responder = Self.responder else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "stub", code: 0))
            return
        }
        let stub = responder(request)
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: stub.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: stub.headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
