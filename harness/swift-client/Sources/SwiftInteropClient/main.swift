import Foundation
import SolanaPayKit

/// Swift interop adapter for the MPP charge harness. Mirrors the
/// command-line shape of `rust/crates/mpp/src/bin/interop_client.rs`:
///
/// - Reads `MPP_INTEROP_TARGET_URL`, `MPP_INTEROP_RPC_URL`, and
///   `MPP_INTEROP_CLIENT_SECRET_KEY` (JSON array of bytes).
/// - Optional `MPP_INTEROP_SETTLEMENT_HEADER` (defaults to
///   `x-fixture-settlement`).
/// - Sends the unauthenticated request, parses the 402 WWW-Authenticate,
///   signs through `PayKit.HttpClient.mpp`, emits one `result` JSON line
///   on stdout, exits 0 on completion (success or paid failure).
///
/// All diagnostics go to stderr. Stdout is reserved for the harness
/// handshake.

struct InteropError: Error { let message: String }

func readEnv(_ name: String) throws -> String {
    guard let value = ProcessInfo.processInfo.environment[name], !value.isEmpty else {
        throw InteropError(message: "\(name) is required")
    }
    return value
}

func readKeypair(_ name: String) throws -> Data {
    let raw = try readEnv(name)
    guard let data = raw.data(using: .utf8) else {
        throw InteropError(message: "\(name) is not valid UTF-8")
    }
    guard
        let bytes = try? JSONSerialization.jsonObject(with: data) as? [Int]
    else {
        throw InteropError(message: "\(name) is not a JSON array of bytes")
    }
    var validated: [UInt8] = []
    validated.reserveCapacity(bytes.count)
    for value in bytes {
        guard value >= 0, value <= 255 else {
            throw InteropError(
                message: "\(name) contains non-byte value \(value); expected 0...255"
            )
        }
        validated.append(UInt8(value))
    }
    return Data(validated)
}

func emitResult(_ status: Int, ok: Bool, headers: [String: String], body: Data, settlement: String?) {
    var payload: [String: Any] = [
        "type": "result",
        "implementation": "swift",
        "role": "client",
        "ok": ok,
        "status": status,
        "responseHeaders": headers,
    ]
    if let settlement = settlement {
        payload["settlement"] = settlement
    } else {
        payload["settlement"] = NSNull()
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
struct InteropEntry {
    static func main() async {
        do {
            let targetURLString = try readEnv("MPP_INTEROP_TARGET_URL")
            guard let targetURL = URL(string: targetURLString) else {
                throw InteropError(message: "MPP_INTEROP_TARGET_URL is not a URL")
            }
            let rpcURLString = try readEnv("MPP_INTEROP_RPC_URL")
            guard let rpcURL = URL(string: rpcURLString) else {
                throw InteropError(message: "MPP_INTEROP_RPC_URL is not a URL")
            }
            let secret = try readKeypair("MPP_INTEROP_CLIENT_SECRET_KEY")
            let settlementHeader = ProcessInfo.processInfo.environment["MPP_INTEROP_SETTLEMENT_HEADER"]
                ?? "x-fixture-settlement"

            let signer = try MemorySigner(secretKey: secret)
            let rpc = RpcClient(endpoint: rpcURL)
            let client = PayKit.HttpClient.mpp(
                signer: signer, rpc: rpc, settlementHeader: settlementHeader
            )

            let response = try await client.request(targetURL).response()
            emitResult(
                response.status,
                ok: (200..<300).contains(response.status),
                headers: response.headers,
                body: response.body,
                settlement: response.settlementSignature
            )
        } catch let error as InteropError {
            writeStderr("interop error: \(error.message)")
            emitResult(0, ok: false, headers: [:], body: Data(error.message.utf8), settlement: nil)
            exit(1)
        } catch {
            writeStderr("unexpected error: \(error)")
            emitResult(0, ok: false, headers: [:], body: Data("\(error)".utf8), settlement: nil)
            exit(1)
        }
    }
}
