import Foundation

/// Namespace for the x402 client interceptors, so each scheme's interceptor is
/// reached as ``X402/Interceptor`` (exact) and ``X402/UptoInterceptor`` (upto).
public enum X402 {}

public extension X402 {
    /// The x402 exact payment interceptor: on a `402` response it parses the
    /// x402 challenge from the response headers and body, builds the
    /// `Payment-Signature` header through the supplied signer, and replays
    /// the request once.
    ///
    /// The x402 exact counterpart of `ChargeInterceptor` (MPP charge), so a
    /// single `PayKit.HttpClient` shape drives both. Drive it through
    /// `PayKit.HttpClient.x402(signer:rpc:selection:)`.
    struct Interceptor: PayKit.PaymentInterceptor {
        public let signer: any SolanaSigner
        public let rpc: RpcClient
        public let selection: X402ChallengeSelection

        public init(
            signer: any SolanaSigner,
            rpc: RpcClient,
            selection: X402ChallengeSelection = X402ChallengeSelection()
        ) {
            self.signer = signer
            self.rpc = rpc
            self.selection = selection
        }

        public func retry(
            _ request: URLRequest,
            for response: HTTPURLResponse,
            body: Data
        ) async throws -> PayKit.RetryResult {
            let rawHeaders = response.headerPairs()
            let bodyStr = String(decoding: body, as: UTF8.self)
            guard let challenge = parseX402ChallengeWithVersion(
                headers: rawHeaders,
                body: bodyStr,
                selection: selection
            ) else {
                throw PayKitError.unsupportedChallenge(
                    method: "x402", intent: "no supported offer in challenge"
                )
            }

            // Emit the version the server's challenge declared: legacy `X-PAYMENT`
            // when it declared v1, otherwise the canonical `PAYMENT-SIGNATURE`.
            let payment = try await buildX402PaymentForChallenge(
                signer: signer,
                rpc: rpc,
                offer: challenge.offer,
                declaredVersion: challenge.declaredVersion
            )

            var retry = request
            retry.setValue(payment.value, forHTTPHeaderField: payment.headerName)
            return .retry(request: retry, paymentSent: payment.value)
        }
    }
}
