import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import X402

@main
struct InteropClient {
    static func main() async throws {
        let target = try readRequiredURL("X402_INTEROP_TARGET_URL")
        let rpc = try readRequiredURL("X402_INTEROP_RPC_URL")
        let network = ProcessInfo.processInfo.environment["X402_INTEROP_NETWORK"] ?? X402.solanaDevnet
        // X402_INTEROP_PREFER_CURRENCIES is the canonical env name across every
        // language adapter (typescript/go/python/ruby all read this name). The
        // harness only sets the canonical name, so the Swift client must read
        // the same one or the preferred-currency loop is silently skipped.
        let currencies = ProcessInfo.processInfo.environment["X402_INTEROP_PREFER_CURRENCIES"]
            .map { $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
        let secret = try readSecretKey("X402_INTEROP_CLIENT_SECRET_KEY")
        let signer = try MemorySolanaSigner(secretKey: secret)

        // Scope note: this interop client adapter is intentionally limited to
        // GET-only x402 protected routes. The harness fixture matrix is GET-only,
        // and using `URLSession.shared.data(from:)` here keeps the discovery
        // request and the subsequent paid request on the same HTTP verb (GET),
        // which is the only verb the fixture servers expose. Non-GET routes
        // (POST/PUT/DELETE with bodies, multipart, streaming, etc.) are out of
        // scope for this adapter — supporting them requires re-issuing the
        // original method+body on the paid retry and is tracked separately.
        let (challengeData, challengeResponse) = try await URLSession.shared.data(from: target)
        let headers = (challengeResponse as? HTTPURLResponse)?.allHeaderFields.reduce(into: [String: String]()) { partial, entry in
            if let key = entry.key as? String, let value = entry.value as? String {
                partial[key] = value
            }
        } ?? [:]
        guard let requirement = try parseX402Challenge(
            headers: headers,
            body: challengeData,
            selection: ChallengeSelection(network: network, currencies: currencies)
        ) else {
            throw X402Error.missingChallenge
        }

        let builder = ExactTransactionBuilder(
            signer: signer,
            blockhashProvider: JsonRpcBlockhashProvider(rpcURL: rpc)
        )
        let payment = try await builder.buildPaymentHeader(for: requirement)
        var request = URLRequest(url: target)
        request.addValue(payment, forHTTPHeaderField: X402.paymentSignatureHeader)
        let (paidData, paidResponse) = try await URLSession.shared.data(for: request)
        let status = (paidResponse as? HTTPURLResponse)?.statusCode ?? 0
        let paidHeaders = (paidResponse as? HTTPURLResponse)?.allHeaderFields.reduce(into: [String: String]()) { partial, entry in
            if let key = entry.key as? String, let value = entry.value as? CustomStringConvertible {
                partial[key.lowercased()] = value.description
            }
        } ?? [:]
        let body = (try? JSONSerialization.jsonObject(with: paidData)) ?? (String(data: paidData, encoding: .utf8) ?? "")
        // JSONSerialization rejects a wrapped Optional (Optional<String>.none
        // bridges to Any but is not a valid JSON value), so the absent-header
        // case has to fall through to NSNull explicitly. Without this the
        // adapter would crash on every response that omits the fixture
        // settlement header instead of emitting a JSON null.
        let result: [String: Any] = [
            "type": "result",
            "implementation": "swift",
            "role": "client",
            "ok": (200..<300).contains(status),
            "status": status,
            "responseHeaders": paidHeaders,
            "responseBody": body,
            "settlement": paidHeaders["x-fixture-settlement"] ?? NSNull(),
        ]
        let encoded = try JSONSerialization.data(withJSONObject: result)
        print(String(data: encoded, encoding: .utf8)!)
    }
}

private func readRequiredURL(_ name: String) throws -> URL {
    guard let value = ProcessInfo.processInfo.environment[name], let url = URL(string: value) else {
        throw X402Error.rpc("\(name) is required")
    }
    return url
}

private func readSecretKey(_ name: String) throws -> [UInt8] {
    guard let value = ProcessInfo.processInfo.environment[name],
          let data = value.data(using: .utf8),
          let parsed = try JSONSerialization.jsonObject(with: data) as? [Int] else {
        throw X402Error.rpc("\(name) is required")
    }
    return try parsed.map {
        guard let byte = UInt8(exactly: $0) else {
            throw X402Error.invalidSecretKeyByte($0)
        }
        return byte
    }
}
