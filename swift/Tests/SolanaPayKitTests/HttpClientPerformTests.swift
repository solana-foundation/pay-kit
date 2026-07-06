import Foundation
import Testing
@testable import SolanaPayKit

// MARK: - PayKit.HttpClient.perform + DataRequest terminator coverage

/// A reference-type flag the stub responder closure can mutate to record that
/// the adapted initial request was actually sent.
private final class AdaptFlag: @unchecked Sendable {
    var value = false
}

/// A test interceptor that returns a fixed `RetryResult`, letting us drive the
/// `HttpClient.perform` retry switch (both `.doNotRetry` and `.retry`) and the
/// `adapt` default without going through a real charge/x402 flow.
private struct FixedInterceptor: PayKit.PaymentInterceptor {
    let result: PayKit.RetryResult
    var adaptHook: (@Sendable (URLRequest) -> URLRequest)?

    func adapt(_ urlRequest: URLRequest) async throws -> URLRequest {
        adaptHook?(urlRequest) ?? urlRequest
    }

    func retry(
        _ request: URLRequest,
        for response: HTTPURLResponse,
        body: Data
    ) async throws -> PayKit.RetryResult {
        result
    }
}

@Suite("PayKit.HttpClient perform + terminators", .serialized)
struct HttpClientPerformTests {
    private func makeSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [PerformStubProtocol.self]
        return URLSession(configuration: config)
    }

    // MARK: - DataResponse.isSuccess

    @Test
    func isSuccessReflectsStatusRange() {
        func response(_ status: Int) -> PayKit.DataResponse {
            PayKit.DataResponse(
                status: status, headers: [:], body: Data(),
                settlementSignature: nil, paymentSent: nil
            )
        }
        #expect(response(200).isSuccess)
        #expect(response(204).isSuccess)
        #expect(!response(199).isSuccess)
        #expect(!response(300).isSuccess)
        #expect(!response(402).isSuccess)
        #expect(!response(500).isSuccess)
    }

    // MARK: - doNotRetry branch

    @Test
    func doNotRetryReturns402Verbatim() async throws {
        PerformStubProtocol.reset()
        PerformStubProtocol.responder = { _ in
            CoverageStubResponse(statusCode: 402, headers: ["x-mark": "orig"], body: Data("challenge".utf8))
        }
        let client = PayKit.HttpClient(
            interceptor: FixedInterceptor(result: .doNotRetry),
            urlSession: makeSession()
        )
        let response = try await client.request(URL(string: "https://example.test/x")!).response()
        // The interceptor declined; the original 402 is surfaced unchanged.
        #expect(response.status == 402)
        #expect(response.paymentSent == nil)
        #expect(response.headers["x-mark"] == "orig")
        // Only one round-trip: no retry.
        #expect(PerformStubProtocol.requestCount == 1)
    }

    // MARK: - retry branch via custom interceptor + adapt

    @Test
    func retryReplaysAndAdaptRunsOnInitialRequest() async throws {
        PerformStubProtocol.reset()
        // Capture whether the initial (non-retry) request carried the adapt
        // header the interceptor's adapt(_:) stamped on.
        let adaptedFlag = AdaptFlag()
        PerformStubProtocol.responder = { req in
            if req.value(forHTTPHeaderField: "X-Retry") == "1" {
                return CoverageStubResponse(
                    statusCode: 200,
                    headers: ["x-fixture-settlement": "DONE"],
                    body: Data("ok".utf8)
                )
            }
            // First (initial) request: record whether adapt ran.
            if req.value(forHTTPHeaderField: "X-Adapted") == "yes" {
                adaptedFlag.value = true
            }
            return CoverageStubResponse(statusCode: 402, headers: [:], body: Data())
        }

        var retryRequest = URLRequest(url: URL(string: "https://example.test/x")!)
        retryRequest.setValue("1", forHTTPHeaderField: "X-Retry")

        let interceptor = FixedInterceptor(
            result: .retry(request: retryRequest, paymentSent: "PAID_TOKEN"),
            adaptHook: { req in
                var adapted = req
                adapted.setValue("yes", forHTTPHeaderField: "X-Adapted")
                return adapted
            }
        )
        let client = PayKit.HttpClient(interceptor: interceptor, urlSession: makeSession())
        let response = try await client.request(URL(string: "https://example.test/x")!).response()

        #expect(response.status == 200)
        #expect(response.paymentSent == "PAID_TOKEN")
        #expect(response.settlementSignature == "DONE")
        #expect(PerformStubProtocol.requestCount == 2)
        // The first (adapted) request carried the adapt header.
        #expect(adaptedFlag.value == true)
    }

    // MARK: - serializingDecodable

    struct Payload: Decodable, Equatable {
        let ok: Bool
        let value: Int
    }

    @Test
    func serializingDecodableDecodesSuccessBody() async throws {
        PerformStubProtocol.reset()
        PerformStubProtocol.responder = { _ in
            CoverageStubResponse(
                statusCode: 200, headers: ["Content-Type": "application/json"],
                body: Data(#"{"ok":true,"value":7}"#.utf8)
            )
        }
        let client = PayKit.HttpClient(
            interceptor: FixedInterceptor(result: .doNotRetry),
            urlSession: makeSession()
        )
        let decoded = try await client
            .request(URL(string: "https://example.test/j")!)
            .serializingDecodable(of: Payload.self)
        #expect(decoded == Payload(ok: true, value: 7))
    }

    @Test
    func serializingDecodableThrowsOnNonSuccessStatus() async {
        PerformStubProtocol.reset()
        PerformStubProtocol.responder = { _ in
            CoverageStubResponse(statusCode: 500, headers: [:], body: Data("boom".utf8))
        }
        let client = PayKit.HttpClient(
            interceptor: FixedInterceptor(result: .doNotRetry),
            urlSession: makeSession()
        )
        await #expect(throws: MppError.self) {
            _ = try await client
                .request(URL(string: "https://example.test/j")!)
                .serializingDecodable(of: Payload.self)
        }
    }

    // MARK: - HTTP method constants

    @Test
    func httpMethodConstantsCarryExpectedRawValues() {
        #expect(PayKit.HTTPMethod.get.rawValue == "GET")
        #expect(PayKit.HTTPMethod.post.rawValue == "POST")
        #expect(PayKit.HTTPMethod.put.rawValue == "PUT")
        #expect(PayKit.HTTPMethod.patch.rawValue == "PATCH")
        #expect(PayKit.HTTPMethod.delete.rawValue == "DELETE")
        #expect(PayKit.HTTPMethod.head.rawValue == "HEAD")
        #expect(PayKit.HTTPMethod(rawValue: "OPTIONS").rawValue == "OPTIONS")
    }
}
