import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - URLProtocol stub (dedicated to the x402 transport suite)

/// A canned response for `X402StubURLProtocol`. Kept separate from the MPP
/// `StubURLProtocol` so the two transport suites never race on shared
/// static state when Swift Testing runs them in parallel.
struct X402StubResponse {
    let statusCode: Int
    let headers: [String: String]
    let body: Data
}

final class X402StubURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responder: ((URLRequest) -> X402StubResponse)?
    nonisolated(unsafe) static var requestCount = 0
    nonisolated(unsafe) static var capturedRequests: [URLRequest] = []

    static func reset() {
        responder = nil
        requestCount = 0
        capturedRequests = []
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requestCount += 1
        Self.capturedRequests.append(request)
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

// MARK: - Transport tests

@Suite("PayKit.HttpClient x402 transport", .serialized)
struct X402TransportTests {
    static func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [X402StubURLProtocol.self]
        return URLSession(configuration: config)
    }

    static func makeClient(session: URLSession) throws -> PayKit.HttpClient {
        let signer = try MemorySigner(secretKey: Data(repeating: 0x01, count: 32))
        let rpc = RpcClient(endpoint: URL(string: "http://localhost:8899")!)
        let selection = X402ChallengeSelection(network: "devnet", currencies: nil)
        return PayKit.HttpClient.x402(signer: signer, rpc: rpc, urlSession: session, selection: selection)
    }

    static func challengeBody() -> Data {
        let blockhash = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"
        let json = """
        {
          "x402Version": 2,
          "accepts": [{
            "scheme": "exact",
            "network": "\(SolanaNetwork.devnet)",
            "amount": "5000",
            "asset": "SOL",
            "payTo": "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
            "extra": { "recentBlockhash": "\(blockhash)" }
          }]
        }
        """
        return Data(json.utf8)
    }

    @Test
    func retryCarriesPaymentSignatureOn402() async throws {
        X402StubURLProtocol.reset()
        X402StubURLProtocol.responder = { req in
            if let psig = req.value(forHTTPHeaderField: "Payment-Signature"), !psig.isEmpty {
                return X402StubResponse(
                    statusCode: 200,
                    headers: [
                        "Content-Type": "application/json",
                        "x-fixture-settlement": "SETTLED_42",
                    ],
                    body: Data(#"{"ok":true}"#.utf8)
                )
            }
            return X402StubResponse(
                statusCode: 402,
                headers: ["Content-Type": "application/json"],
                body: Self.challengeBody()
            )
        }

        let session = Self.makeSession()
        let client = try Self.makeClient(session: session)
        let response = try await client.request(URL(string: "https://example.test/paid")!).response()

        #expect(response.status == 200)
        #expect(X402StubURLProtocol.requestCount == 2)
        #expect(response.settlementSignature == "SETTLED_42")
        #expect(response.paymentSent != nil)

        // The retry request actually carried the header.
        let retry = X402StubURLProtocol.capturedRequests.last
        let sentHeader = retry?.value(forHTTPHeaderField: "Payment-Signature")
        #expect(sentHeader != nil)
        #expect(sentHeader == response.paymentSent)

        // And the header value is a valid base64 payment envelope.
        let envData = Data(base64Encoded: response.paymentSent ?? "")
        #expect(envData != nil)
    }

    @Test
    func non402PassesThroughVerbatimWithNilPaymentSignature() async throws {
        X402StubURLProtocol.reset()
        X402StubURLProtocol.responder = { _ in
            X402StubResponse(
                statusCode: 200,
                headers: ["Content-Type": "text/plain", "x-extra": "kept"],
                body: Data("hello".utf8)
            )
        }

        let session = Self.makeSession()
        let client = try Self.makeClient(session: session)
        let response = try await client.request(URL(string: "https://example.test/free")!).response()

        #expect(response.status == 200)
        #expect(X402StubURLProtocol.requestCount == 1)
        #expect(response.paymentSent == nil)
        #expect(String(decoding: response.body, as: UTF8.self) == "hello")
        // Header collapse uses the typed accessor; value survives verbatim.
        #expect(response.headers["x-extra"] == "kept")
    }

    @Test
    func throwsWhenNoSupportedOfferInChallenge() async throws {
        X402StubURLProtocol.reset()
        X402StubURLProtocol.responder = { _ in
            X402StubResponse(
                statusCode: 402,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"accepts":[{"scheme":"exact","network":"ethereum:1","amount":"1"}]}"#.utf8)
            )
        }
        let session = Self.makeSession()
        let client = try Self.makeClient(session: session)
        do {
            _ = try await client.request(URL(string: "https://example.test/paid")!).response()
            Issue.record("expected unsupportedChallenge")
        } catch {
            // Expected: no Solana exact offer in the challenge.
        }
        #expect(X402StubURLProtocol.requestCount == 1)
    }
}
