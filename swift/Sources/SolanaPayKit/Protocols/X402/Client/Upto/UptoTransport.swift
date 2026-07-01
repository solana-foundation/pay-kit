import Foundation

public extension X402 {
    /// The x402 `upto` payment interceptor: on a `402` response it parses the
    /// `upto` challenge, builds a partially-signed channel `open` plus the
    /// `PAYMENT-SIGNATURE` envelope through the supplied signer, and replays the
    /// request once.
    ///
    /// Parallels ``X402/Interceptor`` (exact scheme) and `ChargeInterceptor`
    /// (MPP charge), so a single `PayKit.HttpClient` shape drives all three.
    /// Drive it through `PayKit.HttpClient.x402Upto(signer:)`.
    struct UptoInterceptor: PayKit.PaymentInterceptor {
        /// Signer that authorizes the channel deposit (the channel payer).
        public let signer: any SolanaSigner
        /// Clock used to derive `expiresAt = now + maxTimeoutSeconds`.
        public let now: @Sendable () -> Date

        public init(
            signer: any SolanaSigner,
            now: @escaping @Sendable () -> Date = { Date() }
        ) {
            self.signer = signer
            self.now = now
        }

        public func retry(
            _ request: URLRequest,
            for response: HTTPURLResponse,
            body: Data
        ) async throws -> PayKit.RetryResult {
            let rawHeaders = response.headerPairs()
            let bodyStr = String(decoding: body, as: UTF8.self)
            guard let requirement = parseUptoChallenge(headers: rawHeaders, body: bodyStr) else {
                throw PayKitError.unsupportedChallenge(
                    method: "x402-upto", intent: "no supported upto offer in challenge"
                )
            }

            let expiresAt = Int(now().timeIntervalSince1970) + requirement.maxTimeoutSeconds
            let payment = try await buildUptoHeader(
                signer: signer, requirements: requirement, expiresAt: expiresAt
            )

            var retry = request
            retry.setValue(payment, forHTTPHeaderField: X402PaymentHeader)
            return .retry(request: retry, paymentSent: payment)
        }
    }
}

public extension PayKit.HttpClient {
    /// A client that drives x402 `upto` (payment-channel) endpoints: on a 402,
    /// parse the `upto` challenge, build a partially-signed channel `open`
    /// through `signer`, and replay with a `Payment-Signature` header.
    static func x402Upto(
        signer: any SolanaSigner,
        urlSession: URLSession = .shared,
        settlementHeader: String = "x-payment-settlement-signature"
    ) -> PayKit.HttpClient {
        PayKit.HttpClient(
            interceptor: X402.UptoInterceptor(signer: signer),
            urlSession: urlSession,
            settlementHeader: settlementHeader
        )
    }
}
