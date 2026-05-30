import Foundation

/// x402-aware HTTP client: send a request, on a 402 response parse the
/// x402 challenge, build the `Payment-Signature` header through the
/// supplied signer, and replay the same request once.
///
/// Mirrors the Python `x402` transport and the rust interop client
/// pattern. This is the high-level entry point for client code; harness
/// adapters call `X402HTTPClient.fetch` and read the `Response`.
public struct X402HTTPClient: Sendable {
    public let urlSession: URLSession
    public let signer: any SolanaSigner
    public let rpc: RpcClient
    public let selection: X402ChallengeSelection

    public init(
        signer: any SolanaSigner,
        rpc: RpcClient,
        urlSession: URLSession = .shared,
        selection: X402ChallengeSelection = X402ChallengeSelection()
    ) {
        self.signer = signer
        self.rpc = rpc
        self.urlSession = urlSession
        self.selection = selection
    }

    public struct Response: Sendable {
        public let status: Int
        /// Lowercased header names.
        public let headers: [String: String]
        public let body: Data
        /// Value of the settlement header if present.
        public let settlementSignature: String?
        /// The `Payment-Signature` header value that was sent, if any.
        public let paymentSignatureSent: String?
    }

    /// GET (or any method) the URL, retrying once with a `Payment-Signature`
    /// header on a 402 response.
    ///
    /// - Parameters:
    ///   - url: The target resource URL.
    ///   - method: HTTP method (defaults to `GET`).
    ///   - additionalHeaders: Extra headers for both the probe and the retry.
    ///   - body: Optional request body.
    ///   - settlementHeader: Name of the fixture settlement header
    ///     (defaults to `"x-fixture-settlement"`).
    public func fetch(
        url: URL,
        method: String = "GET",
        additionalHeaders: [String: String] = [:],
        body: Data? = nil,
        settlementHeader: String = "x-fixture-settlement"
    ) async throws -> Response {
        var probeRequest = URLRequest(url: url)
        probeRequest.httpMethod = method
        for (k, v) in additionalHeaders { probeRequest.setValue(v, forHTTPHeaderField: k) }
        probeRequest.httpBody = body

        let (probeData, probeURLResponse) = try await urlSession.data(for: probeRequest)
        guard let probeHTTP = probeURLResponse as? HTTPURLResponse else {
            throw MppError.rpcFailure("non-HTTP response")
        }

        if probeHTTP.statusCode != 402 {
            return _makeResponse(
                http: probeHTTP, body: probeData,
                settlementHeader: settlementHeader, paymentSignatureSent: nil
            )
        }

        // Parse challenge from response headers + body.
        let rawHeaders = _allHeaders(from: probeHTTP)
        let bodyStr = String(decoding: probeData, as: UTF8.self)
        guard let offer = parseX402Challenge(
            headers: rawHeaders,
            body: bodyStr,
            selection: selection
        ) else {
            throw MppError.unsupportedChallenge(
                method: "x402", intent: "no supported offer in challenge"
            )
        }

        let paymentHeader = try await buildX402PaymentHeader(
            signer: signer, rpc: rpc, offer: offer
        )

        var retryRequest = URLRequest(url: url)
        retryRequest.httpMethod = method
        for (k, v) in additionalHeaders { retryRequest.setValue(v, forHTTPHeaderField: k) }
        retryRequest.setValue(paymentHeader, forHTTPHeaderField: "Payment-Signature")
        retryRequest.httpBody = body

        let (retryData, retryURLResponse) = try await urlSession.data(for: retryRequest)
        guard let retryHTTP = retryURLResponse as? HTTPURLResponse else {
            throw MppError.rpcFailure("non-HTTP response on x402 retry")
        }
        return _makeResponse(
            http: retryHTTP, body: retryData,
            settlementHeader: settlementHeader, paymentSignatureSent: paymentHeader
        )
    }

    // MARK: - Private helpers

    private func _makeResponse(
        http: HTTPURLResponse,
        body: Data,
        settlementHeader: String,
        paymentSignatureSent: String?
    ) -> Response {
        var headers: [String: String] = [:]
        for (rawKey, _) in http.allHeaderFields {
            guard let key = rawKey as? String else { continue }
            // Read each value back through the typed accessor so the value
            // is the canonical header string, never an `Any`'s
            // `String(describing:)` rendering.
            if let value = http.value(forHTTPHeaderField: key) {
                headers[key.lowercased()] = value
            }
        }
        let settlement = headers[settlementHeader.lowercased()]
        return Response(
            status: http.statusCode,
            headers: headers,
            body: body,
            settlementSignature: settlement,
            paymentSignatureSent: paymentSignatureSent
        )
    }

    private func _allHeaders(from http: HTTPURLResponse) -> [(name: String, value: String)] {
        var result: [(name: String, value: String)] = []
        for (rawKey, _) in http.allHeaderFields {
            guard let key = rawKey as? String,
                  let value = http.value(forHTTPHeaderField: key) else { continue }
            result.append((name: key, value: value))
        }
        return result
    }
}
