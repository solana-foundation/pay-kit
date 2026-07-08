import Foundation
import SolanaPayKit

/// Drives a full MPP payment-channel **session** against the playground's
/// `/api/v1/stream` (a metered SSE endpoint), the flow the one-shot charge
/// client can't do:
///
///   1. GET the resource unauthenticated → 402 `WWW-Authenticate` session
///      challenge.
///   2. Open the channel: `PaymentChannelSession.open` builds the payer-signed
///      open transaction; the credential carries it and the server (operator)
///      co-signs + broadcasts. Retrying the GET with that credential returns the
///      200 `text/event-stream`.
///   3. Read the SSE deliveries (`data: {chunk,cost}` … `[DONE]`), summing cost.
///   4. Reserve a delivery on the side channel, then sign + commit one
///      cumulative voucher through `SessionConsumer`.
///   5. Optionally poll the receipt route for the on-chain settle signature.
///
/// Mirrors the TypeScript `SessionFetch` transport, scoped to what the demo
/// needs (aggregate the stream into a single voucher rather than throttled
/// live commits).
enum SessionStream {
    struct Result {
        let channelId: String
        let chunks: Int
        let totalPaidBaseUnits: UInt64
        let cumulative: String
        let settleSignature: String?
        /// Ordered trace of each step's output, surfaced in the log so the flow
        /// is visible (open -> stream -> commit -> settle).
        let steps: [String]
    }

    /// Run the session against `streamURL` (e.g. `<playground>/api/v1/stream`),
    /// paying with `payer` (the funded demo account). Returns a summary for the
    /// log. The voucher signer is a fresh ephemeral key (the on-chain authorized
    /// signer for this channel).
    static func consume(streamURL: URL, payer: SolanaSigner) async throws -> Result {
        let session = URLSession.shared
        var steps: [String] = []

        // 1. Unauthenticated GET → 402 session challenge.
        let challenge = try await fetchChallenge(streamURL, using: session)
        try challenge.requireSolanaSession()
        let request = try challenge.sessionRequest
        guard let blockhash = request.recentBlockhash, !blockhash.isEmpty else {
            throw SessionStreamError.message("session challenge did not carry a recentBlockhash")
        }
        guard let recentSlot = request.recentSlot else {
            throw SessionStreamError.message("session challenge did not carry a recentSlot")
        }

        // 2. Open the channel (pull + clientVoucher, server-broadcast).
        let sessionSigner = try MemorySigner(secretKey: randomSeed())
        let opener = try await PaymentChannelSession.open(
            request: request,
            payerSigner: payer,
            sessionSigner: sessionSigner,
            recentBlockhash: blockhash,
            openSlot: recentSlot
        )
        let channelId = opener.open.channelId.base58
        let credential = try serializeSessionCredential(challenge: challenge.echo(), action: opener.action)
        steps.append("opened channel \(shortId(channelId)) · deposit \(usd(request.cap))")

        // 3. Retry the GET with the open credential → 200 SSE; read deliveries.
        let (chunks, totalCost) = try await readStream(streamURL, authorization: credential, using: session)
        steps.append("streamed \(chunks) chunks · metered \(usd(totalCost))")

        // 4. Reserve one aggregate delivery, then sign + commit the voucher.
        var cumulative = "0"
        if totalCost > 0 {
            let originDeliveries = URL(string: "/__402/session/deliveries", relativeTo: streamURL)?.absoluteURL
                ?? streamURL.deletingLastPathComponent().appendingPathComponent("__402/session/deliveries")
            let commitURL = URL(string: "/__402/session/commit", relativeTo: streamURL)?.absoluteURL
                ?? originDeliveries

            let directive = try await reserveDelivery(
                originDeliveries,
                channelId: channelId,
                amount: totalCost,
                commitURL: commitURL.absoluteString,
                using: session
            )
            let consumer = SessionConsumer(
                session: opener.session,
                transport: HttpCommitTransport(commitURL: commitURL, urlSession: session)
            )
            let receipt = try await consumer.commitDirective(directive)
            cumulative = receipt.cumulative
            steps.append("committed voucher · cumulative \(receipt.cumulative) (\(receipt.status.rawValue))")
        }

        // 5. Best-effort receipt poll for the settle signature (server idle-closes).
        let settle = try? await pollReceipt(streamURL: streamURL, channelId: channelId, using: session)
        steps.append(settle != nil ? "settled on-chain · \(shortId(settle!))" : "settle pending (idle-close runs server-side)")

        return Result(
            channelId: channelId,
            chunks: chunks,
            totalPaidBaseUnits: totalCost,
            cumulative: cumulative,
            settleSignature: settle,
            steps: steps
        )
    }

    // MARK: - Steps

    private static func fetchChallenge(_ url: URL, using session: URLSession) async throws -> PaymentChallenge {
        var req = URLRequest(url: url)
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let (_, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw SessionStreamError.message("no HTTP response from \(url)")
        }
        guard http.statusCode == 402 else {
            throw SessionStreamError.message("expected 402 from \(url.lastPathComponent), got \(http.statusCode)")
        }
        guard let header = http.value(forHTTPHeaderField: "Www-Authenticate") else {
            throw SessionStreamError.message("402 had no WWW-Authenticate header")
        }
        return try MppHeaders.parseWWWAuthenticate(header)
    }

    private static func readStream(
        _ url: URL,
        authorization: String,
        using session: URLSession
    ) async throws -> (chunks: Int, totalCost: UInt64) {
        var req = URLRequest(url: url)
        req.setValue(authorization, forHTTPHeaderField: "Authorization")
        req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        req.timeoutInterval = 60

        let (bytes, response) = try await session.bytes(for: req)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw SessionStreamError.message("stream open failed: HTTP \(code)")
        }

        var chunks = 0
        var total: UInt64 = 0
        for try await line in bytes.lines {
            guard line.hasPrefix("data:") else { continue }
            let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            if payload == "[DONE]" { break }
            guard let data = payload.data(using: .utf8),
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { continue }
            chunks += 1
            if let cost = obj["cost"] as? String, let value = UInt64(cost) {
                total += value
            }
        }
        return (chunks, total)
    }

    private static func reserveDelivery(
        _ url: URL,
        channelId: String,
        amount: UInt64,
        commitURL: String,
        using session: URLSession
    ) async throws -> MeteringDirective {
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        let body: [String: Any] = [
            "amount": String(amount),
            "sessionId": channelId,
            "deliveryId": "mpp-\(UUID().uuidString)",
            "commitUrl": commitURL,
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw SessionStreamError.message("delivery reservation failed: HTTP \(code)")
        }
        return try JSONDecoder().decode(MeteringDirective.self, from: data)
    }

    private static func pollReceipt(
        streamURL: URL,
        channelId: String,
        using session: URLSession
    ) async throws -> String? {
        guard let receiptURL = URL(string: "/sessions/receipt/\(channelId)", relativeTo: streamURL)?.absoluteURL else {
            return nil
        }
        // The server idle-closes after a short delay; poll a few times.
        for _ in 0..<8 {
            try await Task.sleep(nanoseconds: 1_500_000_000)
            let (data, response) = try await session.data(from: receiptURL)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { continue }
            // The program renamed finalize -> seal; accept either receipt flag
            // while playground servers roll over.
            let sealed = (obj["sealed"] as? Bool) ?? (obj["finalized"] as? Bool) ?? false
            if sealed, let sig = obj["settledSignature"] as? String, !sig.isEmpty {
                return sig
            }
        }
        return nil
    }

    private static func randomSeed() -> Data {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }

    private static func shortId(_ value: String) -> String {
        value.count > 14 ? "\(value.prefix(6))…\(value.suffix(6))" : value
    }

    private static func usd(_ baseUnits: UInt64) -> String {
        let dollars = Decimal(baseUnits) / 1_000_000
        return "$\(NSDecimalNumber(decimal: dollars))"
    }

    private static func usd(_ baseUnitsString: String) -> String {
        UInt64(baseUnitsString).map(usd) ?? baseUnitsString
    }
}

/// Posts signed vouchers to the session commit side channel
/// (`POST /__402/session/commit`) and decodes the `CommitReceipt`.
private struct HttpCommitTransport: CommitTransport {
    let commitURL: URL
    let urlSession: URLSession

    func commit(directive: MeteringDirective, payload: CommitPayload) async throws -> CommitReceipt {
        var req = URLRequest(url: commitURL)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.httpBody = try JSONEncoder().encode(payload)
        let (data, response) = try await urlSession.data(for: req)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            let text = String(data: data, encoding: .utf8) ?? ""
            throw SessionStreamError.message("voucher commit failed: HTTP \(code) \(text)")
        }
        return try JSONDecoder().decode(CommitReceipt.self, from: data)
    }
}

enum SessionStreamError: Error, LocalizedError {
    case message(String)
    var errorDescription: String? {
        switch self {
        case .message(let text): return text
        }
    }
}
