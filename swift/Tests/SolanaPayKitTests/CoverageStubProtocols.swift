import Foundation

// MARK: - Dedicated URLProtocol stubs for the coverage suites
//
// Swift Testing runs distinct suites in parallel; the `.serialized` trait only
// orders tests *within* one suite. The existing `StubURLProtocol` (shared by
// `HTTPClientTests`) and `X402StubURLProtocol` therefore cannot be reused by
// the new coverage suites without racing on their mutable static state. Each
// new suite gets its own protocol class below so its static state is isolated.

/// Stub used by `RpcClientTests`.
final class RpcClientStubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responder: ((URLRequest) -> CoverageStubResponse)?
    nonisolated(unsafe) static var errorToThrow: Error?

    static func reset() {
        responder = nil
        errorToThrow = nil
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
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
            url: request.url!, statusCode: stub.statusCode,
            httpVersion: "HTTP/1.1", headerFields: stub.headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// Stub used by `HttpClientPerformTests`.
final class PerformStubProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var responder: ((URLRequest) -> CoverageStubResponse)?
    nonisolated(unsafe) static var requestCount = 0

    static func reset() {
        responder = nil
        requestCount = 0
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.requestCount += 1
        guard let responder = Self.responder else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "stub", code: 0))
            return
        }
        let stub = responder(request)
        let response = HTTPURLResponse(
            url: request.url!, statusCode: stub.statusCode,
            httpVersion: "HTTP/1.1", headerFields: stub.headers
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// A canned response shared by the coverage-suite stubs above.
struct CoverageStubResponse {
    let statusCode: Int
    let headers: [String: String]
    let body: Data
}
