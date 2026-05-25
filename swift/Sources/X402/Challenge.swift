import Foundation

public struct ChallengeSelection: Sendable {
    public var network: String?
    public var currencies: [String]?

    public init(network: String? = nil, currencies: [String]? = nil) {
        self.network = network
        self.currencies = currencies
    }
}

public struct PaymentRequirement: Equatable, Codable {
    public let scheme: String
    public let network: String
    public let amount: String
    public let asset: String
    public let payTo: String
    public let maxTimeoutSeconds: Int?
    public let extra: [String: JSONValue]?

    public var feePayer: String? {
        extra?["feePayer"]?.string ?? extra?["feePayerKey"]?.string
    }

    public var memo: String? {
        extra?["memo"]?.string
    }

    public var tokenProgram: String {
        extra?["tokenProgram"]?.string ?? X402.tokenProgram
    }

    /// Resolve `extra.tokenProgram` against the canonical SPL allowlist.
    /// Defaults to the SPL Token classic program when the field is absent.
    /// Throws `X402Error.unsupportedTokenProgram` for any value
    /// outside `{ SPL Token, Token-2022 }` so a malicious server cannot
    /// trick the client into signing a transaction that invokes an
    /// arbitrary executable program.
    public func validatedTokenProgram() throws -> String {
        let value = extra?["tokenProgram"]?.string ?? X402.tokenProgram
        guard value == X402.tokenProgram || value == X402.token2022Program else {
            throw X402Error.unsupportedTokenProgram(value)
        }
        return value
    }

    /// Parse the `extra.decimals` field from the payment requirement.
    /// Throws `X402Error.invalidDecimals` if the value is non-integral or outside `0...255`.
    /// Defaults to `6` when the field is absent (canonical USDC precision).
    public func decimals() throws -> UInt8 {
        guard case .number(let value) = extra?["decimals"] else {
            return 6
        }
        // Reject NaN, infinity, negatives, fractions, and anything outside UInt8 range.
        guard value.isFinite,
              value >= 0,
              value <= Double(UInt8.max),
              value.rounded(.towardZero) == value else {
            throw X402Error.invalidDecimals(value)
        }
        return UInt8(value)
    }
}

struct PaymentRequiredEnvelope: Codable {
    let x402Version: Int?
    let accepts: [PaymentRequirement]
}

public func parseX402Challenge(
    headers: [String: String],
    body: Data?,
    selection: ChallengeSelection = ChallengeSelection()
) throws -> PaymentRequirement? {
    if let header = headers.first(where: { $0.key.lowercased() == X402.paymentRequiredHeader.lowercased() })?.value,
       let decoded = Data(base64Encoded: header),
       let requirement = try selectRequirement(from: decoded, selection: selection) {
        return requirement
    }
    if let body, let requirement = try selectRequirement(from: body, selection: selection) {
        return requirement
    }
    return nil
}

private func selectRequirement(from data: Data, selection: ChallengeSelection) throws -> PaymentRequirement? {
    let envelope = try JSONDecoder().decode(PaymentRequiredEnvelope.self, from: data)
    if let version = envelope.x402Version, version != X402.x402Version {
        throw X402Error.unsupportedX402Version(version)
    }
    let preferredNetwork = canonicalNetwork(selection.network ?? X402.solanaMainnet)
    let solana = envelope.accepts.filter { requirement in
        requirement.scheme == X402.exactScheme && requirement.network.starts(with: "solana:")
    }
    // Reject any requirement that pins extra.tokenProgram to a program outside
    // the canonical SPL allowlist before it can ever reach the transaction builder.
    for requirement in solana {
        _ = try requirement.validatedTokenProgram()
    }
    let onNetwork = solana.filter { canonicalNetwork($0.network) == preferredNetwork }
    // Fail-closed network selection.
    //
    // If the caller explicitly pinned `selection.network` (e.g. "devnet") and the
    // server's accept list does not include any offer on that network, we MUST NOT
    // silently widen to the full Solana set — that would let a server which only
    // advertises mainnet offers convince a devnet-intending client to sign and
    // broadcast a real-funds mainnet transaction. Throw `unsupportedNetwork`
    // instead so the caller sees an explicit failure.
    //
    // Widening is only safe when the caller did not specify a network at all
    // (`selection.network == nil`), in which case the default mainnet preference
    // is itself a soft default and falling back to any solana offer preserves
    // existing behavior without crossing a network boundary the caller cared about.
    let candidates: [PaymentRequirement]
    if onNetwork.isEmpty {
        if selection.network != nil {
            throw X402Error.unsupportedNetwork(preferredNetwork)
        }
        candidates = solana
    } else {
        candidates = onNetwork
    }
    if let currencies = selection.currencies, !currencies.isEmpty {
        for currency in currencies {
            if let match = candidates.first(where: { currencyMatches(offered: $0.asset, accepted: currency, network: $0.network) }) {
                return match
            }
        }
        return nil
    }
    return candidates.min { lhs, rhs in
        (UInt64(lhs.amount) ?? UInt64.max) < (UInt64(rhs.amount) ?? UInt64.max)
    }
}

private func canonicalNetwork(_ network: String) -> String {
    switch network {
    case "devnet", "solana-devnet", X402.solanaDevnet:
        return X402.solanaDevnet
    case "mainnet", "mainnet-beta", X402.solanaMainnet:
        return X402.solanaMainnet
    case "testnet", "solana-testnet", X402.solanaTestnet:
        return X402.solanaTestnet
    default:
        return network
    }
}

/// Canonical stablecoin mint table.
/// MUST mirror the TypeScript reference `STABLECOIN_MINTS` exactly.
/// Source: typescript/packages/x402/src/protocol/schemes/exact/constants.ts lines 89-111.
enum StablecoinMints {
    // USDC — TS constants.ts:40-42
    static let usdcMainnet = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    static let usdcDevnet  = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    static let usdcTestnet = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    // USDT — TS constants.ts:43
    static let usdtMainnet = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
    // USDG — TS constants.ts:44-46
    static let usdgMainnet = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
    static let usdgDevnet  = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
    static let usdgTestnet = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
    // PYUSD — TS constants.ts:47-49
    static let pyusdMainnet = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
    static let pyusdDevnet  = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
    static let pyusdTestnet = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
    // CASH (mainnet only) — TS constants.ts:50
    static let cashMainnet = "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"

    /// Per-network resolution mirroring TS `STABLECOIN_MINTS` (constants.ts:89-111).
    static func mints(forSymbol symbol: String) -> [String: String] {
        switch symbol.uppercased() {
        case "USDC":
            return [
                X402.solanaMainnet: usdcMainnet,
                X402.solanaDevnet:  usdcDevnet,
                X402.solanaTestnet: usdcTestnet,
            ]
        case "USDT":
            return [X402.solanaMainnet: usdtMainnet]
        case "USDG":
            return [
                X402.solanaMainnet: usdgMainnet,
                X402.solanaDevnet:  usdgDevnet,
                X402.solanaTestnet: usdgTestnet,
            ]
        case "PYUSD":
            return [
                X402.solanaMainnet: pyusdMainnet,
                X402.solanaDevnet:  pyusdDevnet,
                X402.solanaTestnet: pyusdTestnet,
            ]
        case "CASH":
            return [X402.solanaMainnet: cashMainnet]
        default:
            return [:]
        }
    }
}

/// Match an offered mint address against an accepted currency symbol.
/// Resolves the symbol through the canonical `STABLECOIN_MINTS` table
/// (TS reference: typescript/packages/x402/src/protocol/schemes/exact/constants.ts:89-111)
/// across mainnet/devnet/testnet. Falls back to direct equality so a caller
/// that already passes a mint string still matches. Unknown symbols return
/// `false` so the selector can fall through to the cheapest-offer branch.
private func currencyMatches(offered: String, accepted: String, network: String) -> Bool {
    if offered == accepted { return true }
    let table = StablecoinMints.mints(forSymbol: accepted)
    if table.isEmpty { return false }
    let canonical = canonicalNetwork(network)
    if let pinned = table[canonical], pinned == offered { return true }
    // Cross-network: still allow a symbol match if the offered mint appears
    // anywhere in the table for that symbol. This preserves selection when a
    // server lists a devnet mint while the client preference is "mainnet".
    return table.values.contains(offered)
}
