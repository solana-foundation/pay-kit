import Foundation
import Security
import SolanaPayKit

// ⚠️⚠️⚠️ DEMO ACCOUNT — DO NOT USE IN PRODUCTION ⚠️⚠️⚠️
//
// `DemoSigner` is the app's account store. The 32-byte Ed25519 seed is
// generated on first "Setup Account" and persisted in iOS Keychain
// under the demo service tag. Topup uses Surfpool cheatcodes
// (`surfnet_setAccount` / `surfnet_setTokenAccount`) against the
// configured RPC, which means it only works on a Surfpool sandbox
// (hosted `402.surfnet.dev:8899` by default, or local Surfpool).
//
// For real applications, swap this for a `SolanaSigner` implementation
// that delegates signing to either:
//   - Solana Mobile Wallet Adapter (the canonical iOS/Android path), or
//   - Solana Seeker Seed Vault (hardware-backed on Seeker devices).
// The `SolanaSigner` protocol is the single integration point.

enum DemoSigner {
    private static let keychainService = "dev.solana-mpp.paykitdemo"
    private static let keychainAccount = "demo-signer-seed"

    private static let usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    private static let tokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    private static let systemProgram = "11111111111111111111111111111111"

    /// Topup amounts. 100 SOL for fees, 1000 USDC (× 1e6) for payments.
    static let topupLamports: UInt64 = 100_000_000_000
    static let topupUsdcBaseUnits: UInt64 = 1_000_000_000

    /// Load an existing signer from Keychain, or `nil` if Setup Account
    /// has not run yet.
    static func loadSigner() throws -> MemorySigner? {
        guard let seed = try readSeed() else { return nil }
        return try MemorySigner(secretKey: seed)
    }

    /// Generate a fresh 32-byte Ed25519 seed, persist it in Keychain,
    /// and return the corresponding signer. Overwrites any existing
    /// seed under the same service/account.
    static func setupSigner() throws -> MemorySigner {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw DemoSignerError.randomFailed(OSStatus: status)
        }
        let seed = Data(bytes)
        try writeSeed(seed)
        return try MemorySigner(secretKey: seed)
    }

    /// Delete the persisted seed. Safe to call when none is stored.
    static func resetSigner() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw DemoSignerError.keychainWriteFailed(OSStatus: status)
        }
    }

    /// Seed an account on Surfpool with SOL + USDC via the surfnet
    /// cheatcodes. Idempotent — re-running just resets the balances.
    /// Only works on a Surfpool RPC (hosted sandbox or local Surfpool).
    static func topup(rpc: URL, pubkey: String) async throws {
        try await rpcCall(
            url: rpc,
            method: "surfnet_setAccount",
            params: [
                .string(pubkey),
                .object([
                    "lamports": .uint(topupLamports),
                    "data": .string(""),
                    "executable": .bool(false),
                    "owner": .string(systemProgram),
                ]),
            ]
        )
        try await rpcCall(
            url: rpc,
            method: "surfnet_setTokenAccount",
            params: [
                .string(pubkey),
                .string(usdcMint),
                .object(["amount": .uint(topupUsdcBaseUnits)]),
                .string(tokenProgram),
            ]
        )
    }

    // MARK: - Keychain plumbing

    private static func readSeed() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else {
                throw DemoSignerError.invalidStoredSeed
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw DemoSignerError.keychainReadFailed(OSStatus: status)
        }
    }

    private static func writeSeed(_ seed: Data) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        // Try update first; fall back to add. Avoids the duplicate-item
        // error path on the second Setup tap.
        let update = SecItemUpdate(
            base as CFDictionary,
            [kSecValueData as String: seed] as CFDictionary
        )
        if update == errSecSuccess { return }
        if update != errSecItemNotFound {
            throw DemoSignerError.keychainWriteFailed(OSStatus: update)
        }
        var add = base
        add[kSecValueData as String] = seed
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw DemoSignerError.keychainWriteFailed(OSStatus: addStatus)
        }
    }

    // MARK: - RPC

    /// Fetch the USDC balance (in decimal USDC, accounting for the
    /// 6-decimal mint) for `pubkey` on the given Surfpool RPC. Returns
    /// `nil` when the ATA does not exist yet (i.e. the account has not
    /// been topped up).
    static func usdcBalance(rpc: URL, pubkey: String) async throws -> Decimal? {
        let owner = try Pubkey(base58: pubkey)
        let mint = try Pubkey(base58: usdcMint)
        let tokenProgramPk = try Pubkey(base58: tokenProgram)
        let ata = try AssociatedTokenAccount.address(
            owner: owner, mint: mint, tokenProgram: tokenProgramPk
        )
        do {
            let json = try await rpcCallResult(
                url: rpc,
                method: "getTokenAccountBalance",
                params: [.string(ata.base58)]
            )
            guard let result = json["result"] as? [String: Any],
                  let value = result["value"] as? [String: Any],
                  let uiAmount = value["uiAmountString"] as? String,
                  let decimal = Decimal(string: uiAmount) else {
                return nil
            }
            return decimal
        } catch DemoSignerError.rpcError(let detail) where detail.contains("could not find account") {
            return nil
        }
    }

    private static func rpcCallResult(
        url: URL,
        method: String,
        params: [JSONValue]
    ) async throws -> [String: Any] {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: JSONValue] = [
            "jsonrpc": .string("2.0"),
            "id": .uint(1),
            "method": .string(method),
            "params": .array(params),
        ]
        request.httpBody = try JSONValue.object(body).encoded()
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw DemoSignerError.rpcTransport("Non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let snippet = String(data: data, encoding: .utf8) ?? "<binary>"
            throw DemoSignerError.rpcHttp(status: http.statusCode, body: snippet)
        }
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        if let errorField = json["error"] {
            throw DemoSignerError.rpcError(String(describing: errorField))
        }
        return json
    }

    private static func rpcCall(url: URL, method: String, params: [JSONValue]) async throws {
        // Surface JSON-RPC `error` field — Surfpool returns it for
        // unknown methods or invalid params (e.g. when pointing at a
        // mainnet RPC that has no surfnet cheatcodes).
        _ = try await rpcCallResult(url: url, method: method, params: params)
    }
}

enum DemoSignerError: Error, LocalizedError {
    case randomFailed(OSStatus: OSStatus)
    case invalidStoredSeed
    case keychainReadFailed(OSStatus: OSStatus)
    case keychainWriteFailed(OSStatus: OSStatus)
    case rpcTransport(String)
    case rpcHttp(status: Int, body: String)
    case rpcError(String)

    var errorDescription: String? {
        switch self {
        case .randomFailed(let status):
            return "SecRandomCopyBytes failed (OSStatus \(status))"
        case .invalidStoredSeed:
            return "Stored seed is not 32 bytes. Reset the account."
        case .keychainReadFailed(let status):
            return "Keychain read failed (OSStatus \(status))"
        case .keychainWriteFailed(let status):
            return "Keychain write failed (OSStatus \(status))"
        case .rpcTransport(let detail):
            return "RPC transport error: \(detail)"
        case .rpcHttp(let status, let body):
            return "RPC HTTP \(status): \(body)"
        case .rpcError(let detail):
            return "RPC error: \(detail)"
        }
    }
}

// MARK: - Minimal JSON encoder

/// Tiny JSON value type so the RPC payload preserves the exact integer
/// width Surfpool expects (`u64` lamports / token amounts). Using
/// `JSONSerialization` with `[String: Any]` boxes ints as `NSNumber`,
/// which serializes large `UInt64` values as floats and corrupts them.
private indirect enum JSONValue {
    case string(String)
    case uint(UInt64)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    func encoded() throws -> Data {
        var bytes: [UInt8] = []
        write(into: &bytes)
        return Data(bytes)
    }

    private func write(into out: inout [UInt8]) {
        switch self {
        case .string(let s):
            out.append(UInt8(ascii: "\""))
            for scalar in s.unicodeScalars {
                switch scalar {
                case "\"": out.append(contentsOf: [0x5C, 0x22])
                case "\\": out.append(contentsOf: [0x5C, 0x5C])
                case "\n": out.append(contentsOf: [0x5C, 0x6E])
                case "\r": out.append(contentsOf: [0x5C, 0x72])
                case "\t": out.append(contentsOf: [0x5C, 0x74])
                default:
                    if scalar.value < 0x20 {
                        let hex = String(format: "\\u%04x", scalar.value)
                        out.append(contentsOf: hex.utf8)
                    } else {
                        out.append(contentsOf: String(scalar).utf8)
                    }
                }
            }
            out.append(UInt8(ascii: "\""))
        case .uint(let n):
            out.append(contentsOf: String(n).utf8)
        case .bool(let b):
            out.append(contentsOf: (b ? "true" : "false").utf8)
        case .null:
            out.append(contentsOf: "null".utf8)
        case .array(let xs):
            out.append(UInt8(ascii: "["))
            for (i, x) in xs.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                x.write(into: &out)
            }
            out.append(UInt8(ascii: "]"))
        case .object(let obj):
            out.append(UInt8(ascii: "{"))
            for (i, key) in obj.keys.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                JSONValue.string(key).write(into: &out)
                out.append(UInt8(ascii: ":"))
                obj[key]!.write(into: &out)
            }
            out.append(UInt8(ascii: "}"))
        }
    }
}
