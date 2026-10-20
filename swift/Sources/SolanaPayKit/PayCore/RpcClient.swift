import Foundation

/// Minimal Solana JSON-RPC client used by `Charge` when the server
/// omits `recentBlockhash` from `methodDetails`. The harness
/// always includes `recentBlockhash`, so this path is only exercised
/// for ad-hoc callers that want the SDK to fetch one.
///
/// URLSession-backed, no third-party dependency. Methods:
/// `getLatestBlockhash`, `getAccountOwner`, `getMintAccount`, and
/// `sendTransaction`. All speak the JSON-RPC shape Solana's RPC endpoint
/// expects.
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
            throw PayKitError.rpcFailure("getLatestBlockhash returned malformed body")
        }
        let bytes = try Base58.decode(blockhashStr)
        guard bytes.count == 32 else {
            throw PayKitError.rpcFailure("blockhash is not 32 bytes")
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
        guard let outer = result as? [String: Any] else {
            throw PayKitError.rpcFailure("getAccountInfo returned malformed body for \(pubkeyBase58)")
        }
        guard let value = outer["value"] as? [String: Any] else {
            throw PayKitError.rpcFailure("account \(pubkeyBase58) does not exist")
        }
        guard let owner = value["owner"] as? String else {
            throw PayKitError.rpcFailure("account \(pubkeyBase58) has no owner field (does it exist?)")
        }
        return owner
    }

    /// Reads an SPL mint account and returns its owning token program and
    /// decimals.
    ///
    /// Fails closed: a missing account, an owner other than the Token or
    /// Token-2022 program, or data that is not an initialized mint all
    /// throw `PayKitError.invalidTransaction`. The MPP charge client uses
    /// this when the challenge omits `tokenProgram`, and the x402 exact
    /// client uses it to learn the decimals for `TransferChecked` when the
    /// offer does not carry them (scheme_exact_svm.md keeps decimals out of
    /// `extra`).
    public func getMintAccount(mintBase58: String) async throws -> MintAccount {
        let result = try await rpcCall(
            method: "getAccountInfo",
            params: [mintBase58, ["encoding": "base64"]]
        )
        guard let outer = result as? [String: Any] else {
            throw PayKitError.rpcFailure("getAccountInfo returned malformed body for \(mintBase58)")
        }
        guard let value = outer["value"] as? [String: Any] else {
            throw PayKitError.invalidTransaction("mint account \(mintBase58) does not exist")
        }
        guard let ownerStr = value["owner"] as? String else {
            throw PayKitError.invalidTransaction("mint account \(mintBase58) has no owner")
        }
        guard
            let dataField = value["data"] as? [Any],
            let encoded = dataField.first as? String,
            let data = Data(base64Encoded: encoded)
        else {
            throw PayKitError.invalidTransaction("mint account \(mintBase58) has no base64 data")
        }
        return try MintAccount(mint: mintBase58, owner: ownerStr, data: data)
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
            throw PayKitError.rpcFailure("sendTransaction returned non-string result")
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
            throw PayKitError.rpcFailure("non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw PayKitError.rpcFailure("RPC HTTP \(http.statusCode)")
        }
        let parsed = try JSONSerialization.jsonObject(with: data)
        guard let object = parsed as? [String: Any] else {
            throw PayKitError.rpcFailure("RPC body is not an object")
        }
        if let error = object["error"] as? [String: Any] {
            let message = (error["message"] as? String) ?? "unknown error"
            let code = (error["code"] as? Int) ?? 0
            throw PayKitError.rpcFailure("RPC error \(code): \(message)")
        }
        guard let result = object["result"] else {
            throw PayKitError.rpcFailure("RPC body missing result field")
        }
        return result
    }
}

/// An SPL mint account read from the chain. Only constructible from an
/// account owned by the Token or Token-2022 program whose data is an
/// initialized mint, so holding one proves the token program and decimals
/// came from the mint itself.
public struct MintAccount: Sendable, Equatable {
    /// SPL mint layout size; Token-2022 mints with extensions are longer
    /// but keep the same base layout.
    static let baseLength = 82
    /// Byte offsets in the base layout: `decimals` (u8) and
    /// `is_initialized` (bool) follow `mint_authority` (36) and `supply` (8).
    static let decimalsOffset = 44
    static let initializedOffset = 45

    /// Owning program: `Pubkey.tokenProgram` or `Pubkey.token2022Program`.
    public let tokenProgram: Pubkey
    public let decimals: UInt8

    /// Parses a mint account from its owner and raw account data.
    public init(mint: String, owner: String, data: Data) throws {
        let ownerKey = try Pubkey(base58: owner)
        guard ownerKey == .tokenProgram || ownerKey == .token2022Program else {
            throw PayKitError.invalidTransaction(
                "mint \(mint) is owned by unsupported program \(owner)"
            )
        }
        let bytes = [UInt8](data)
        guard bytes.count >= Self.baseLength, bytes[Self.initializedOffset] == 1 else {
            throw PayKitError.invalidTransaction("account \(mint) is not an initialized SPL mint")
        }
        self.tokenProgram = ownerKey
        self.decimals = bytes[Self.decimalsOffset]
    }
}
