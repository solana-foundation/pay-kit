import Foundation

/// MPP-aware HTTP client: send a request, on a 402 response pick the
/// solana+charge challenge from the response headers, build a pull-mode
/// credential through the supplied signer, and replay the same request
/// once with the `Authorization: Payment ...` header attached.
///
/// Retry semantics:
///
/// - 402 response: parse `WWW-Authenticate`, sign, replay once. Any
///   status other than 200..<300 on the replay is returned verbatim.
/// - Non-402 status (success, 4xx other than 402, 5xx): returned
///   unchanged.
/// - Transport error: thrown to the caller; no retry.
///
/// Only one MPP retry per call. The client does not retry on transport
/// errors, 5xx responses, or any non-402 status; the caller decides
/// whether to issue a new request.
public struct MppHTTPClient: Sendable {
    public let urlSession: URLSession
    public let signer: any SolanaSigner
    public let rpc: RpcClient?
    public let chargeOptions: Charge.Options

    public init(
        signer: any SolanaSigner,
        rpc: RpcClient? = nil,
        urlSession: URLSession = .shared,
        chargeOptions: Charge.Options = Charge.Options()
    ) {
        self.signer = signer
        self.rpc = rpc
        self.urlSession = urlSession
        self.chargeOptions = chargeOptions
    }

    public struct Response: Sendable {
        public let status: Int
        public let headers: [String: String]
        public let body: Data
        public let settlementSignature: String?
    }

    /// Fetches the given URL with optional headers, retrying once on a
    /// 402 status with a freshly built MPP credential.
    public func fetch(
        url: URL,
        method: String = "GET",
        additionalHeaders: [String: String] = [:],
        body: Data? = nil,
        settlementHeader: String = "x-fixture-settlement"
    ) async throws -> Response {
        var request = URLRequest(url: url)
        request.httpMethod = method
        for (k, v) in additionalHeaders { request.setValue(v, forHTTPHeaderField: k) }
        request.httpBody = body

        let (firstData, firstResponse) = try await urlSession.data(for: request)
        guard let firstHttp = firstResponse as? HTTPURLResponse else {
            throw MppError.rpcFailure("non-HTTP response")
        }
        if firstHttp.statusCode != 402 {
            return responseFor(http: firstHttp, body: firstData, settlementHeader: settlementHeader)
        }

        let challenges = wwwAuthenticateValues(from: firstHttp)
        let challenge = try Charge.pickChallenge(wwwAuthenticateHeaders: challenges)
        let authorization = try await Charge.buildPullCredential(
            challenge: challenge,
            signer: signer,
            rpc: rpc,
            options: chargeOptions
        )

        var retry = URLRequest(url: url)
        retry.httpMethod = method
        for (k, v) in additionalHeaders { retry.setValue(v, forHTTPHeaderField: k) }
        retry.setValue(authorization, forHTTPHeaderField: "Authorization")
        retry.httpBody = body

        let (retryData, retryResponse) = try await urlSession.data(for: retry)
        guard let retryHttp = retryResponse as? HTTPURLResponse else {
            throw MppError.rpcFailure("non-HTTP response on MPP retry")
        }
        return responseFor(http: retryHttp, body: retryData, settlementHeader: settlementHeader)
    }

    private func responseFor(http: HTTPURLResponse, body: Data, settlementHeader: String) -> Response {
        var headers: [String: String] = [:]
        for (rawKey, rawValue) in http.allHeaderFields {
            guard let key = (rawKey as? String)?.lowercased() else { continue }
            headers[key] = String(describing: rawValue)
        }
        let settlement = headers[settlementHeader.lowercased()]
        return Response(
            status: http.statusCode,
            headers: headers,
            body: body,
            settlementSignature: settlement
        )
    }

    private func wwwAuthenticateValues(from response: HTTPURLResponse) -> [String] {
        // HTTPURLResponse joins multi-value WWW-Authenticate with comma
        // commas in the value would corrupt naive splitting, so use
        // `value(forHTTPHeaderField:)` directly and fall back to the
        // single combined header.
        if let combined = response.value(forHTTPHeaderField: "WWW-Authenticate")
            ?? response.value(forHTTPHeaderField: "Www-Authenticate")
            ?? response.value(forHTTPHeaderField: "www-authenticate") {
            return Self.splitWWWAuthenticate(combined)
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
