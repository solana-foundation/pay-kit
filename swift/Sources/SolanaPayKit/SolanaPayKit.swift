import Foundation

/// `PayKit` is the umbrella namespace for the public client surface,
/// modeled on Alamofire's design: one reusable client created with
/// config, a fluent request builder, and payment handled by an
/// interceptor (the way Alamofire layers a `RequestInterceptor` over a
/// `Session`).
///
/// ```swift
/// import SolanaPayKit
///
/// let signer = try MemorySigner(secretKey: secretKeyData)
/// let rpc = RpcClient(endpoint: URL(string: "https://402.surfnet.dev")!)
/// let client = PayKit.HttpClient.mpp(signer: signer, rpc: rpc)
///
/// let response = try await client
///     .request(URL(string: "https://api.example.com/paid")!)
///     .response()
/// print(response.status)              // 200 after the payment retry
/// print(response.settlementSignature) // base58 on-chain signature
/// ```
///
/// The caseless `enum` form gives a pure namespace: it cannot be
/// instantiated, only used to qualify nested types like
/// `PayKit.HttpClient`.
public enum PayKit {}

// MARK: - HTTP method

public extension PayKit {
    /// HTTP method for a `PayKit` request. Mirrors Alamofire's
    /// `HTTPMethod` value type: a small, expressive wrapper over the
    /// method string rather than a raw `String` at the call site.
    struct HTTPMethod: RawRepresentable, Hashable, Sendable {
        public let rawValue: String
        public init(rawValue: String) { self.rawValue = rawValue }

        public static let get = HTTPMethod(rawValue: "GET")
        public static let post = HTTPMethod(rawValue: "POST")
        public static let put = HTTPMethod(rawValue: "PUT")
        public static let patch = HTTPMethod(rawValue: "PATCH")
        public static let delete = HTTPMethod(rawValue: "DELETE")
        public static let head = HTTPMethod(rawValue: "HEAD")
    }
}

// MARK: - Payment interceptor

public extension PayKit {
    /// The outcome of an interceptor's retry decision, mirroring
    /// Alamofire's `RetryResult`: either replay the (adapted) request or
    /// surface the original response unchanged.
    enum RetryResult: Sendable {
        /// Replay with the adapted request. `paymentSent` is the payment
        /// header value that was attached, surfaced on `DataResponse` so
        /// callers can observe what was paid.
        case retry(request: URLRequest, paymentSent: String)
        /// Do not retry; return the response verbatim.
        case doNotRetry
    }

    /// A payment interceptor adapts the outgoing request and, on a
    /// payment-required response, builds a credential and decides whether
    /// to replay. This is the `RequestInterceptor` analog from Alamofire:
    /// `adapt` corresponds to `RequestAdapter`, `retry` to
    /// `RequestRetrier`. The MPP charge flow and the x402 exact flow are
    /// each one concrete interceptor, so a single `HttpClient` shape
    /// drives both protocols.
    protocol PaymentInterceptor: Sendable {
        /// Adapt the initial request before it is sent. Default: identity.
        func adapt(_ urlRequest: URLRequest) async throws -> URLRequest

        /// Decide whether to retry after receiving `response`. The
        /// interceptor parses the challenge, builds the credential through
        /// its signer, and returns `.retry` with the request to replay, or
        /// `.doNotRetry` to pass the response through.
        func retry(
            _ request: URLRequest,
            for response: HTTPURLResponse,
            body: Data
        ) async throws -> RetryResult
    }
}

public extension PayKit.PaymentInterceptor {
    func adapt(_ urlRequest: URLRequest) async throws -> URLRequest { urlRequest }
}

// MARK: - Response

public extension PayKit {
    /// The result of a `PayKit` request after any payment retry. Carries
    /// the final status and headers, the raw body, the on-chain
    /// settlement signature when the server surfaced one, and the payment
    /// header value that was sent (the MPP `Authorization: Payment ...`
    /// value, or the x402 `Payment-Signature` value).
    struct DataResponse: Sendable {
        public let status: Int
        /// Lowercased header names.
        public let headers: [String: String]
        public let body: Data
        /// Value of the settlement header if present.
        public let settlementSignature: String?
        /// The payment header value that was sent on the retry, if any.
        public let paymentSent: String?

        /// `true` when the final status is in `200..<300`.
        public var isSuccess: Bool { (200..<300).contains(status) }
    }
}

// MARK: - Client (the Alamofire `Session` analog)

public extension PayKit {
    /// A reusable, `URLSession`-backed payment client. Build it once with
    /// a signer-driven interceptor and issue many requests, exactly the
    /// way an Alamofire `Session` is configured once and reused.
    ///
    /// Retry semantics are owned by the interceptor: send the request,
    /// and on a payment-required (`402`) response let the interceptor
    /// build a credential and replay once. Any non-402 status is returned
    /// verbatim; transport errors propagate without a retry.
    struct HttpClient: Sendable {
        public let urlSession: URLSession
        public let interceptor: any PaymentInterceptor
        /// Header the client reads the settlement signature from.
        public let settlementHeader: String

        /// Designated initializer. Prefer the `.mpp` / `.x402` factories
        /// unless you supply a custom interceptor.
        public init(
            interceptor: any PaymentInterceptor,
            urlSession: URLSession = .shared,
            settlementHeader: String = "x-fixture-settlement"
        ) {
            self.interceptor = interceptor
            self.urlSession = urlSession
            self.settlementHeader = settlementHeader
        }

        /// A client that drives MPP `solana/charge` endpoints: on a 402,
        /// parse `WWW-Authenticate: Payment ...`, sign through `signer`,
        /// and replay with `Authorization: Payment ...`.
        public static func mpp(
            signer: any SolanaSigner,
            rpc: RpcClient? = nil,
            urlSession: URLSession = .shared,
            chargeOptions: Charge.Options = Charge.Options(),
            settlementHeader: String = "x-fixture-settlement"
        ) -> HttpClient {
            HttpClient(
                interceptor: ChargeInterceptor(
                    signer: signer, rpc: rpc, chargeOptions: chargeOptions
                ),
                urlSession: urlSession,
                settlementHeader: settlementHeader
            )
        }

        /// A client that drives x402 `exact` endpoints: on a 402, parse
        /// the x402 challenge, sign through `signer`, and replay with a
        /// `Payment-Signature` header.
        public static func x402(
            signer: any SolanaSigner,
            rpc: RpcClient,
            urlSession: URLSession = .shared,
            selection: X402ChallengeSelection = X402ChallengeSelection(),
            settlementHeader: String = "x-fixture-settlement"
        ) -> HttpClient {
            HttpClient(
                interceptor: X402Interceptor(
                    signer: signer, rpc: rpc, selection: selection
                ),
                urlSession: urlSession,
                settlementHeader: settlementHeader
            )
        }

        /// Begin a fluent request. Returns a `DataRequest` value whose
        /// `.response()` / `.serializingDecodable(of:)` terminators run
        /// the request and apply the payment retry.
        public func request(
            _ url: URL,
            method: HTTPMethod = .get,
            headers: [String: String] = [:],
            body: Data? = nil
        ) -> DataRequest {
            DataRequest(client: self, url: url, method: method, headers: headers, body: body)
        }
    }
}

// MARK: - Request (the Alamofire `DataRequest` analog)

public extension PayKit {
    /// A pending request bound to a client. Holds the request inputs and
    /// exposes async terminators that execute it, applying the client's
    /// payment interceptor. Built via `HttpClient.request(_:)`.
    struct DataRequest: Sendable {
        let client: HttpClient
        let url: URL
        let method: HTTPMethod
        let headers: [String: String]
        let body: Data?

        /// Execute the request and return the raw `DataResponse`, after
        /// any single payment retry the interceptor performs.
        public func response() async throws -> DataResponse {
            try await client.perform(
                url: url, method: method, headers: headers, body: body
            )
        }

        /// Execute the request and decode the response body as `T`. Throws
        /// `MppError.rpcFailure` when the final status is not 2xx, so the
        /// happy path is a clean decode. Mirrors Alamofire's
        /// `serializingDecodable`.
        public func serializingDecodable<T: Decodable>(
            of type: T.Type,
            decoder: JSONDecoder = JSONDecoder()
        ) async throws -> T {
            let response = try await response()
            guard response.isSuccess else {
                throw MppError.rpcFailure(
                    "request to \(url.absoluteString) failed with status \(response.status)"
                )
            }
            return try decoder.decode(T.self, from: response.body)
        }
    }
}

// MARK: - Client execution

extension PayKit.HttpClient {
    /// Send, then let the interceptor decide on a single payment retry.
    func perform(
        url: URL,
        method: PayKit.HTTPMethod,
        headers: [String: String],
        body: Data?
    ) async throws -> PayKit.DataResponse {
        var initial = URLRequest(url: url)
        initial.httpMethod = method.rawValue
        for (name, value) in headers { initial.setValue(value, forHTTPHeaderField: name) }
        initial.httpBody = body
        initial = try await interceptor.adapt(initial)

        let (firstData, firstResponse) = try await urlSession.data(for: initial)
        guard let firstHTTP = firstResponse as? HTTPURLResponse else {
            throw MppError.rpcFailure("non-HTTP response")
        }

        guard firstHTTP.statusCode == 402 else {
            return Self.makeResponse(
                http: firstHTTP, body: firstData,
                settlementHeader: settlementHeader, paymentSent: nil
            )
        }

        switch try await interceptor.retry(initial, for: firstHTTP, body: firstData) {
        case .doNotRetry:
            return Self.makeResponse(
                http: firstHTTP, body: firstData,
                settlementHeader: settlementHeader, paymentSent: nil
            )
        case let .retry(retryRequest, paymentSent):
            let (retryData, retryResponse) = try await urlSession.data(for: retryRequest)
            guard let retryHTTP = retryResponse as? HTTPURLResponse else {
                throw MppError.rpcFailure("non-HTTP response on payment retry")
            }
            return Self.makeResponse(
                http: retryHTTP, body: retryData,
                settlementHeader: settlementHeader, paymentSent: paymentSent
            )
        }
    }

    static func makeResponse(
        http: HTTPURLResponse,
        body: Data,
        settlementHeader: String,
        paymentSent: String?
    ) -> PayKit.DataResponse {
        var headers: [String: String] = [:]
        for (rawKey, _) in http.allHeaderFields {
            guard let key = rawKey as? String else { continue }
            // Read the value back through the typed accessor so it is the
            // canonical header string, never an `Any`'s `String(describing:)`.
            if let value = http.value(forHTTPHeaderField: key) {
                headers[key.lowercased()] = value
            }
        }
        return PayKit.DataResponse(
            status: http.statusCode,
            headers: headers,
            body: body,
            settlementSignature: headers[settlementHeader.lowercased()],
            paymentSent: paymentSent
        )
    }
}
