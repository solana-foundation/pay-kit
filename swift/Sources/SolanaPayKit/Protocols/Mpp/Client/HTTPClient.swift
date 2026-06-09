import Foundation

/// The MPP charge payment interceptor: on a `402` response it picks the
/// `solana/charge` challenge from `WWW-Authenticate`, builds a pull-mode
/// credential through the supplied signer, and replays the request once
/// with the `Authorization: Payment ...` header attached.
///
/// This is the `RequestInterceptor` (Alamofire) for the MPP charge
/// protocol. Drive it through `PayKit.HttpClient.mpp(signer:rpc:)`.
///
/// Retry semantics (owned here, exercised by `PayKit.HttpClient`):
///
/// - 402 response: parse `WWW-Authenticate`, sign, replay once.
/// - Non-402 status: returned unchanged (the client never calls `retry`).
/// - Transport error: thrown to the caller; no retry.
///
/// Only one charge retry per request: `retry` builds exactly one
/// credential and the client replays exactly once.
public struct ChargeInterceptor: PayKit.PaymentInterceptor {
    public let signer: any SolanaSigner
    public let rpc: RpcClient?
    public let chargeOptions: Charge.Options

    public init(
        signer: any SolanaSigner,
        rpc: RpcClient? = nil,
        chargeOptions: Charge.Options = Charge.Options()
    ) {
        self.signer = signer
        self.rpc = rpc
        self.chargeOptions = chargeOptions
    }

    public func retry(
        _ request: URLRequest,
        for response: HTTPURLResponse,
        body: Data
    ) async throws -> PayKit.RetryResult {
        let challenges = Self.wwwAuthenticateValues(from: response)
        let challenge = try Charge.pickChallenge(wwwAuthenticateHeaders: challenges)
        let authorization = try await Charge.buildPullCredential(
            challenge: challenge,
            signer: signer,
            rpc: rpc,
            options: chargeOptions
        )

        var retry = request
        retry.setValue(authorization, forHTTPHeaderField: "Authorization")
        return .retry(request: retry, paymentSent: authorization)
    }

    // MARK: - WWW-Authenticate parsing

    static func wwwAuthenticateValues(from response: HTTPURLResponse) -> [String] {
        // HTTPURLResponse joins multi-value WWW-Authenticate with comma;
        // commas in the value would corrupt naive splitting, so use
        // `value(forHTTPHeaderField:)` directly and fall back to the
        // single combined header.
        if let combined = response.value(forHTTPHeaderField: "WWW-Authenticate")
            ?? response.value(forHTTPHeaderField: "Www-Authenticate")
            ?? response.value(forHTTPHeaderField: "www-authenticate") {
            return splitWWWAuthenticate(combined)
        }
        return []
    }

    /// Splits a comma-joined `WWW-Authenticate` header into per-challenge
    /// strings. Each challenge in the MPP spec starts with `Payment` (the
    /// scheme); we use that token as the boundary so commas inside
    /// quoted auth-params do not break the split.
    static func splitWWWAuthenticate(_ combined: String) -> [String] {
        let trimmed = combined.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return [] }
        var results: [String] = []
        var current = ""
        var index = trimmed.startIndex
        // ASCII byte view + per-position prefix probe avoids the O(n^2)
        // remaining.lowercased() copy that ran on every character of the
        // header. The MPP scheme name is fixed ASCII so case-insensitive
        // prefix-matching one slot at a time stays O(1) per step.
        let paymentLower: [UInt8] = Array("payment".utf8)
        while index < trimmed.endIndex {
            // Probe for the "Payment" scheme at this position case-insensitively
            // without copying the remaining suffix.
            var hasPaymentPrefix = false
            if let endProbe = trimmed.index(index, offsetBy: paymentLower.count, limitedBy: trimmed.endIndex) {
                let probe = trimmed[index..<endProbe]
                let bytes = Array(probe.utf8)
                if bytes.count == paymentLower.count {
                    var matched = true
                    for byteIndex in 0..<paymentLower.count {
                        // ASCII case-fold by setting bit 0x20 on letters.
                        var byte = bytes[byteIndex]
                        if byte >= 0x41, byte <= 0x5A { byte |= 0x20 }
                        if byte != paymentLower[byteIndex] {
                            matched = false
                            break
                        }
                    }
                    hasPaymentPrefix = matched
                }
            }
            if hasPaymentPrefix {
                if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    results.append(trimRightComma(current))
                }
                current = ""
            }
            // Consume one character; advance through quoted strings to
            // avoid splitting on commas inside auth-params.
            let ch = trimmed[index]
            current.append(ch)
            if ch == "\"" {
                index = trimmed.index(after: index)
                while index < trimmed.endIndex {
                    let inside = trimmed[index]
                    current.append(inside)
                    index = trimmed.index(after: index)
                    if inside == "\\" {
                        if index < trimmed.endIndex {
                            current.append(trimmed[index])
                            index = trimmed.index(after: index)
                        }
                    } else if inside == "\"" {
                        break
                    }
                }
            } else {
                index = trimmed.index(after: index)
            }
        }
        if !current.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            results.append(trimRightComma(current))
        }
        return results
    }

    private static func trimRightComma(_ s: String) -> String {
        var out = s
        while out.last == "," || out.last?.isWhitespace == true {
            out.removeLast()
        }
        return out
    }
}
