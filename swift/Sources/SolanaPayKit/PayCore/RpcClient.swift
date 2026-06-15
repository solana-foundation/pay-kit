import Foundation

/// Minimal Solana JSON-RPC client used by `Charge` when the server
/// omits `recentBlockhash` from `methodDetails`. The harness
/// always includes `recentBlockhash`, so this path is only exercised
/// for ad-hoc callers that want the SDK to fetch one.
///
/// URLSession-backed, no third-party dependency. Three methods:
/// `getLatestBlockhash`, `getAccountOwner`, and `sendTransaction`. All
/// speak the JSON-RPC shape Solana's RPC endpoint expects.
public struct RpcClient: Sendable {
    public let endpoint: URL
    private let urlSession: URLSession

    public init(endpoint: URL, urlSession: URLSession = .shared) {
        self.endpoint = endpoint
        self.urlSession = urlSession
    }

    /// Returns the most recent blockhash from the RPC's `confirmed`
    /// commitment level as a 32-byte value plus its base58 form.
    ///
    /// `confirmed` (not `processed`) is passed explicitly per audit #36:
    /// a `processed` blockhash can disappear under a reorg, leaving the
    /// client holding a signed transaction that fails with
    /// `BlockhashNotFound` after broadcast.
    public func getLatestBlockhash() async throws -> (bytes: Data, base58: String) {
        let response = try await rpcCall(
            method: "getLatestBlockhash",
            params: [["commitment": "confirmed"]]
        )
        guard
            let outer = response as? [String: Any],
            let value = (outer["value"] as? [String: Any]),
            let blockhashStr = value["blockhash"] as? String
        else {
            throw MppError.rpcFailure("getLatestBlockhash returned malformed body")
        }
        let bytes = try Base58.decode(blockhashStr)
        guard bytes.count == 32 else {
            throw MppError.rpcFailure("blockhash is not 32 bytes")
        }
        return (bytes: bytes, base58: blockhashStr)
    }

    /// Returns the base58-encoded owner program of an account. Used by
    /// the charge client to resolve a mint's token program when the
    /// server omits `methodDetails.tokenProgram`, mirroring the Rust
    /// `client::charge::resolve_token_program` path.
    public func getAccountOwner(pubkeyBase58: String) async throws -> String {
        let result = try await rpcCall(
            method: "getAccountInfo",
            params: [pubkeyBase58, ["encoding": "base64"]]
        )
        guard
            let outer = result as? [String: Any],
            let value = outer["value"] as? [String: Any]
        else {
            throw MppError.rpcFailure("getAccountInfo returned malformed body for \(pubkeyBase58)")
        }
        guard let owner = value["owner"] as? String else {
            throw MppError.rpcFailure("account \(pubkeyBase58) has no owner field (does it exist?)")
        }
        return owner
    }

    /// Submits a base64-encoded signed transaction. Returns the base58
    /// signature the RPC echoes back.
    public func sendTransaction(_ base64SignedTx: String, skipPreflight: Bool = false) async throws -> String {
        let options: [String: Any] = [
            "encoding": "base64",
            "skipPreflight": skipPreflight,
        ]
        let result = try await rpcCall(method: "sendTransaction", params: [base64SignedTx, options])
        guard let signature = result as? String else {
            throw MppError.rpcFailure("sendTransaction returned non-string result")
        }
        return signature
    }

    private func rpcCall(method: String, params: [Any]) async throws -> Any {
        let body: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        ]
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, urlResponse) = try await urlSession.data(for: request)
        guard let http = urlResponse as? HTTPURLResponse else {
            throw MppError.rpcFailure("non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw MppError.rpcFailure("RPC HTTP \(http.statusCode)")
        }
        let parsed = try JSONSerialization.jsonObject(with: data)
        guard let object = parsed as? [String: Any] else {
            throw MppError.rpcFailure("RPC body is not an object")
        }
        if let error = object["error"] as? [String: Any] {
            let message = (error["message"] as? String) ?? "unknown error"
            let code = (error["code"] as? Int) ?? 0
            throw MppError.rpcFailure("RPC error \(code): \(message)")
        }
        guard let result = object["result"] else {
            throw MppError.rpcFailure("RPC body missing result field")
        }
        return result
    }
}
