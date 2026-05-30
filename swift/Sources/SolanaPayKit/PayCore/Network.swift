import Foundation

// MARK: - CAIP-2 network identifiers

/// Solana CAIP-2 network identifiers for the canonical clusters.
public enum SolanaNetwork {
    /// Mainnet-beta (canonical CAIP-2 id).
    public static let mainnet = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    /// Devnet CAIP-2 id (Surfpool / pay_kit test net).
    public static let devnet = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    /// Testnet CAIP-2 id (mirrors rust `SOLANA_TESTNET`).
    public static let testnet = "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"

    /// Return the CAIP-2 id for a cluster slug or CAIP-2 string.
    ///
    /// Accepts:
    /// - A full CAIP-2 id (returned unchanged if it is a known Solana id).
    /// - A slug: `"mainnet"`, `"mainnet-beta"`, `"devnet"`, `"localnet"`,
    ///   `"solana"`, `"solana-devnet"`.
    ///
    /// Defaults to `mainnet` for unrecognised values, mirroring the rust
    /// `caip2_network_for_cluster` function.
    public static func caip2(for network: String?) -> String {
        guard let raw = network?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else {
            return mainnet
        }
        if raw == mainnet || raw == devnet || raw == testnet { return raw }
        switch raw.lowercased() {
        case "mainnet", "mainnet-beta", "solana":
            return mainnet
        case "devnet", "solana-devnet", "localnet":
            return devnet
        case "testnet", "solana-testnet":
            return testnet
        default:
            return mainnet
        }
    }

    /// Return a human-readable cluster label (`"mainnet"` / `"devnet"` /
    /// `"testnet"`) for a CAIP-2 id. Used by the mint registry to pick the
    /// right address.
    public static func clusterLabel(for caip2: String) -> String {
        switch caip2 {
        case devnet: return "devnet"
        case testnet: return "testnet"
        default: return "mainnet"
        }
    }
}
