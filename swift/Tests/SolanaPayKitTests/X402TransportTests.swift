import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - Session-scoped URLProtocol stub

struct X402StubResponse {
    let statusCode: Int
    let headers: [String: String]
    let body: Data
}

/// Each test owns a session and its request history. The registry only routes
/// requests, so parallel tests cannot replace or clear another test's responder.
final class X402StubSession: @unchecked Sendable {
    private let id = UUID().uuidString
    private let state: X402StubURLProtocol.State
    let session: URLSession

    init(responder: @escaping (URLRequest) -> X402StubResponse) {
        state = X402StubURLProtocol.State(responder: responder)
        X402StubURLProtocol.register(state, id: id)
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [X402StubURLProtocol.self]
        config.httpAdditionalHeaders = [X402StubURLProtocol.sessionHeader: id]
        session = URLSession(configuration: config)
    }

    var capturedRequests: [URLRequest] { state.capturedRequests }
    var requestCount: Int { capturedRequests.count }

    deinit {
        session.invalidateAndCancel()
        X402StubURLProtocol.unregister(id: id)
    }
}

final class X402StubURLProtocol: URLProtocol, @unchecked Sendable {
    static let sessionHeader = "X-Test-Session-ID"
    private static let lock = NSLock()
    nonisolated(unsafe) private static var states: [String: State] = [:]

    final class State: @unchecked Sendable {
        private let lock = NSLock()
        private let responder: (URLRequest) -> X402StubResponse
        private var requests: [URLRequest] = []

        init(responder: @escaping (URLRequest) -> X402StubResponse) {
            self.responder = responder
        }

        var capturedRequests: [URLRequest] { lock.withLock { requests } }

        func respond(to request: URLRequest) -> X402StubResponse {
            lock.withLock {
                requests.append(request)
                return responder(request)
            }
        }
    }

    static func register(_ state: State, id: String) {
        lock.withLock { states[id] = state }
    }

    static func unregister(id: String) {
        _ = lock.withLock { states.removeValue(forKey: id) }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let id = request.value(forHTTPHeaderField: Self.sessionHeader) ?? ""
        guard let state = Self.lock.withLock({ Self.states[id] }) else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "stub", code: 0))
            return
        }
        let stub = state.respond(to: request)
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

@Suite("PayKit.HttpClient x402 transport")
struct X402TransportTests {
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
        let stub = X402StubSession(responder: { req in
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
        })

        let session = stub.session
        let client = try Self.makeClient(session: session)
        let response = try await client.request(URL(string: "https://example.test/paid")!).response()

        #expect(response.status == 200)
        #expect(stub.requestCount == 2)
        #expect(response.settlementSignature == "SETTLED_42")
        #expect(response.paymentSent != nil)

        // The retry request actually carried the header.
        let retry = stub.capturedRequests.last
        let sentHeader = retry?.value(forHTTPHeaderField: "Payment-Signature")
        #expect(sentHeader != nil)
        #expect(sentHeader == response.paymentSent)

        // And the header value is a valid base64 payment envelope.
        let envData = Data(base64Encoded: response.paymentSent ?? "")
        #expect(envData != nil)
    }

    @Test
    func non402PassesThroughVerbatimWithNilPaymentSignature() async throws {
        let stub = X402StubSession(responder: { _ in
            X402StubResponse(
                statusCode: 200,
                headers: ["Content-Type": "text/plain", "x-extra": "kept"],
                body: Data("hello".utf8)
            )
        })

        let session = stub.session
        let client = try Self.makeClient(session: session)
        let response = try await client.request(URL(string: "https://example.test/free")!).response()

        #expect(response.status == 200)
        #expect(stub.requestCount == 1)
        #expect(response.paymentSent == nil)
        #expect(String(decoding: response.body, as: UTF8.self) == "hello")
        // Header collapse uses the typed accessor; value survives verbatim.
        #expect(response.headers["x-extra"] == "kept")
    }

    @Test
    func throwsWhenNoSupportedOfferInChallenge() async throws {
        let stub = X402StubSession(responder: { _ in
            X402StubResponse(
                statusCode: 402,
                headers: ["Content-Type": "application/json"],
                body: Data(#"{"accepts":[{"scheme":"exact","network":"ethereum:1","amount":"1"}]}"#.utf8)
            )
        })
        let session = stub.session
        let client = try Self.makeClient(session: session)
        do {
            _ = try await client.request(URL(string: "https://example.test/paid")!).response()
            Issue.record("expected unsupportedChallenge")
        } catch {
            // Expected: no Solana exact offer in the challenge.
        }
        #expect(stub.requestCount == 1)
    }
}
