import Foundation
import SolanaPayKit

/// Swift x402 exact harness adapter. Mirrors the Python `harness/python-x402-client/main.py`
/// and the rust `rust/crates/x402/src/bin/harness_client.rs` env contract:
///
/// Env variables:
///   X402_HARNESS_TARGET_URL        - required, the gated resource URL
///   X402_HARNESS_RPC_URL           - required, Solana RPC (blockhash fallback)
///   X402_HARNESS_NETWORK           - CAIP-2 / slug; default devnet CAIP-2
///   X402_HARNESS_CLIENT_SECRET_KEY - required, JSON int array (seed || pubkey)
///   X402_HARNESS_PREFER_CURRENCIES - optional, comma-separated preference list
///
/// Flow: GET target -> parse x402 challenge -> buildX402PaymentHeader ->
/// GET with Payment-Signature -> print ONE JSON line on stdout.

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

func emitResult(
    ok: Bool,
    status: Int,
    headers: [String: String],
    body: Data,
    paymentSignatureSent: String?,
    settlement: String?,
    error: String? = nil
) {
    var payload: [String: Any] = [
        "type": "result",
        "implementation": "swift-x402",
        "role": "client",
        "ok": ok,
        "status": status,
        "responseHeaders": headers,
        "settlement": settlement as Any,
    ]
    if let psig = paymentSignatureSent {
        var h = headers
        h["Payment-Signature-sent"] = psig
        payload["responseHeaders"] = h
    }
    if let error = error {
        payload["error"] = error
    }
    let parsedBody: Any = (try? JSONSerialization.jsonObject(with: body))
        ?? String(decoding: body, as: UTF8.self)
    payload["responseBody"] = parsedBody

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
            let rpcURLString = try readEnv("X402_HARNESS_RPC_URL")
            guard let rpcURL = URL(string: rpcURLString) else {
                throw HarnessError(message: "X402_HARNESS_RPC_URL is not a valid URL")
            }

            let network = ProcessInfo.processInfo.environment["X402_HARNESS_NETWORK"]
                ?? SolanaNetwork.devnet
            let secret = try readKeypair("X402_HARNESS_CLIENT_SECRET_KEY")

            let preferRaw = ProcessInfo.processInfo.environment["X402_HARNESS_PREFER_CURRENCIES"]
            let currencies: [String]?
            if let raw = preferRaw, !raw.isEmpty {
                let parsed = raw.split(separator: ",").map {
                    $0.trimmingCharacters(in: .whitespaces)
                }.filter { !$0.isEmpty }
                currencies = parsed.isEmpty ? nil : parsed
            } else {
                currencies = nil
            }

            let settlementHeader = ProcessInfo.processInfo.environment["X402_HARNESS_SETTLEMENT_HEADER"]
                ?? "x-fixture-settlement"

            let signer = try MemorySigner(secretKey: secret)
            let rpc = RpcClient(endpoint: rpcURL)
            let selection = X402ChallengeSelection(network: network, currencies: currencies)
            let client = PayKit.HttpClient.x402(
                signer: signer, rpc: rpc, selection: selection, settlementHeader: settlementHeader
            )

            let response = try await client.request(targetURL).response()

            emitResult(
                ok: (200..<300).contains(response.status),
                status: response.status,
                headers: response.headers,
                body: response.body,
                paymentSignatureSent: response.paymentSent,
                settlement: response.settlementSignature
            )
        } catch let error as HarnessError {
            writeStderr("harness error: \(error.message)")
            emitResult(
                ok: false, status: 0, headers: [:],
                body: Data(error.message.utf8),
                paymentSignatureSent: nil, settlement: nil,
                error: error.message
            )
            exit(1)
        } catch {
            writeStderr("unexpected error: \(error)")
            let msg = "\(error)"
            emitResult(
                ok: false, status: 0, headers: [:],
                body: Data(msg.utf8),
                paymentSignatureSent: nil, settlement: nil,
                error: msg
            )
            exit(1)
        }
    }
}
