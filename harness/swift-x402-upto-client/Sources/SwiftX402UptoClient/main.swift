import Foundation
import SolanaPayKit

/// Swift x402 `upto` (payment-channel) harness adapter. Mirrors the Python
/// `harness/python-x402-upto-client/main.py` and the Go/Rust upto clients:
///
/// Env variables:
///   X402_HARNESS_TARGET_URL        - required, the gated resource URL
///   X402_HARNESS_CLIENT_SECRET_KEY - required, JSON int array (seed || pubkey)
///   X402_HARNESS_NETWORK           - optional CAIP-2 / slug (diagnostics only)
///
/// Flow: GET target -> parse upto challenge -> buildUptoHeader (expiresAt =
/// now + maxTimeoutSeconds) -> GET with Payment-Signature -> print ONE result
/// JSON line on stdout. Diagnostics go to stderr.

struct HarnessError: Error { let message: String }


func readEnv(_ name: String) throws -> String {
    guard let value = ProcessInfo.processInfo.environment[name], !value.isEmpty else {
        throw HarnessError(message: "\(name) is required")
    }
    return value
}

func readKeypair(_ name: String) throws -> Data {
    let raw = try readEnv(name)
    guard let data = raw.data(using: .utf8),
          let bytes = try? JSONSerialization.jsonObject(with: data) as? [Int] else {
        throw HarnessError(message: "\(name) is not a JSON array of bytes")
    }
    var validated: [UInt8] = []
    validated.reserveCapacity(bytes.count)
    for value in bytes {
        guard value >= 0, value <= 255 else {
            throw HarnessError(message: "\(name) contains non-byte value \(value)")
        }
        validated.append(UInt8(value))
    }
    return Data(validated)
}

func parseBody(_ body: Data) -> Any {
    (try? JSONSerialization.jsonObject(with: body)) ?? String(decoding: body, as: UTF8.self)
}

func emitResult(
    ok: Bool,
    status: Int,
    headers: [String: String],
    body: Any,
    settlement: String?,
    error: String? = nil
) {
    var payload: [String: Any] = [
        "type": "result",
        "implementation": "swift",
        "role": "client",
        "ok": ok,
        "status": status,
        "responseHeaders": headers,
        "responseBody": body,
        // Use NSNull for an absent settlement: a wrapped `nil as Any` is not a
        // valid JSONSerialization value and would drop the whole result line.
        "settlement": settlement ?? NSNull(),
    ]
    if let error { payload["error"] = error }
    let data = (try? JSONSerialization.data(withJSONObject: payload)) ?? Data("{}".utf8)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

func writeStderr(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

@main
struct HarnessEntry {
    static func main() async {
        do {
            let targetURLString = try readEnv("X402_HARNESS_TARGET_URL")
            guard let targetURL = URL(string: targetURLString) else {
                throw HarnessError(message: "X402_HARNESS_TARGET_URL is not a valid URL")
            }
            let secret = try readKeypair("X402_HARNESS_CLIENT_SECRET_KEY")
            let signer = try MemorySigner(secretKey: secret)

            // `x402Upto` defaults `settlementHeader` to the harness settlement
            // header, so it is not repeated here.
            let client = PayKit.HttpClient.x402Upto(signer: signer)
            let response = try await client.request(targetURL).response()

            var headers = response.headers
            if let psig = response.paymentSent {
                headers["\(X402PaymentHeader)-sent"] = psig
            }
            emitResult(
                ok: response.isSuccess,
                status: response.status,
                headers: headers,
                body: parseBody(response.body),
                settlement: response.settlementSignature
            )
        } catch let error as HarnessError {
            writeStderr("harness error: \(error.message)")
            emitResult(
                ok: false, status: 0, headers: [:],
                body: error.message, settlement: nil, error: error.message
            )
            exit(1)
        } catch {
            writeStderr("unexpected error: \(error)")
            let msg = "\(error)"
            emitResult(
                ok: false, status: 0, headers: [:],
                body: msg, settlement: nil, error: msg
            )
            exit(1)
        }
    }
}
