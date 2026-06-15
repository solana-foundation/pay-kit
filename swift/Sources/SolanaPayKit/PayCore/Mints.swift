import Foundation

// MARK: - Stablecoin mint registry

/// Well-known SPL stablecoin mint addresses indexed by symbol.
///
/// Mirrors the rust `protocol::schemes::exact::mints` module and the
/// `Charge.resolveStablecoinMint` Swift function so both x402 and MPP
/// clients share a single source of truth.
public enum Mints {
    // MARK: USDC

    public static let usdcMainnet = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    public static let usdcDevnet  = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    /// Testnet mirrors devnet (matches rust `USDC_TESTNET = USDC_DEVNET`).
    public static let usdcTestnet = usdcDevnet

    // MARK: USDT

    public static let usdtMainnet = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"

    // MARK: USDG

    public static let usdgMainnet = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH"
    public static let usdgDevnet  = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7"
    /// Testnet mirrors devnet (matches rust `USDG_TESTNET = USDG_DEVNET`).
    public static let usdgTestnet = usdgDevnet

    // MARK: PYUSD

    public static let pyusdMainnet = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
    public static let pyusdDevnet  = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"
    /// Testnet mirrors devnet (matches rust `PYUSD_TESTNET = PYUSD_DEVNET`).
    public static let pyusdTestnet = pyusdDevnet

    // MARK: CASH

    public static let cashMainnet  = "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH"

    // MARK: - Resolution helpers

    /// Resolve a currency symbol or mint address to an on-chain mint address.
    ///
    /// Returns `nil` for native SOL (the caller interprets `nil` as the native
    /// SOL path). Returns the input unchanged when it is not a recognised symbol
    /// (pass-through for already-resolved mint addresses). Mirrors
    /// `rust::protocol::schemes::exact::resolve_stablecoin_mint`.
    ///
    /// - Parameters:
    ///   - currency: A symbol (`"USDC"`, `"USDT"`, …) or a raw mint address.
    ///   - cluster: A cluster label (`"devnet"` / `nil` for mainnet) used to
    ///     pick the correct address for multi-network stablecoins.
    public static func resolveMint(currency: String, cluster: String?) -> String? {
        let label = cluster?.lowercased()
        let isDevnet = label == "devnet" || label == "localnet"
        let isTestnet = label == "testnet"
        switch currency.uppercased() {
        case "SOL": return nil
        case "USDC": return isDevnet ? usdcDevnet : (isTestnet ? usdcTestnet : usdcMainnet)
        case "USDT": return usdtMainnet
        case "USDG": return isDevnet ? usdgDevnet : (isTestnet ? usdgTestnet : usdgMainnet)
        case "PYUSD": return isDevnet ? pyusdDevnet : (isTestnet ? pyusdTestnet : pyusdMainnet)
        case "CASH": return cashMainnet
        default: return currency  // pass-through: already a mint address
        }
    }

    /// Resolve a currency symbol or mint address for the **MPP charge** path.
    ///
    /// Mirrors rust `solana_mpp::protocol::solana::resolve_stablecoin_mint`:
    ///   - `"devnet"` → devnet mint
    ///   - `"testnet"` → testnet mint (aliases the devnet mint address)
    ///   - `"localnet"`, `"mainnet"`, `"mainnet-beta"`, `nil`, or any unknown
    ///     value → mainnet mint (Surfpool localnet mirrors mainnet).
    ///
    /// This deliberately differs from the x402 `exact` rule in `resolveMint`,
    /// where `localnet` maps to the devnet mint.
    public static func resolveChargeMint(currency: String, network: String?) -> String? {
        let label = network?.lowercased()
        let isDevnet  = label == "devnet"
        let isTestnet = label == "testnet"
        // localnet and all other values fall through to mainnet: Surfpool localnet
        // mirrors mainnet mints for the charge path (differs from x402 exact path
        // where localnet maps to devnet).
        switch currency.uppercased() {
        case "SOL": return nil
        case "USDC": return isDevnet ? usdcDevnet : (isTestnet ? usdcTestnet : usdcMainnet)
        case "USDT": return usdtMainnet
        case "USDG": return isDevnet ? usdgDevnet : (isTestnet ? usdgTestnet : usdgMainnet)
        case "PYUSD": return isDevnet ? pyusdDevnet : (isTestnet ? pyusdTestnet : pyusdMainnet)
        case "CASH": return cashMainnet
        default: return currency  // pass-through: already a mint address
        }
    }

    // MARK: - Token program resolution

    /// Canonical SPL Token program id.
    public static let tokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    /// Canonical SPL Token-2022 program id.
    public static let token2022Program = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

    /// Reverse lookup: known mint address or symbol to canonical symbol.
    /// Returns `nil` for native SOL or unknown values. Mirrors rust
    /// `stablecoin_symbol`.
    public static func stablecoinSymbol(_ currencyOrMint: String) -> String? {
        if currencyOrMint.uppercased() == "SOL" { return nil }
        switch currencyOrMint.uppercased() {
        case "USDC": return "USDC"
        case "USDT": return "USDT"
        case "USDG": return "USDG"
        case "PYUSD": return "PYUSD"
        case "CASH": return "CASH"
        default:
            switch currencyOrMint {
            case usdcMainnet, usdcDevnet: return "USDC"
            case usdtMainnet: return "USDT"
            case usdgMainnet, usdgDevnet: return "USDG"
            case pyusdMainnet, pyusdDevnet: return "PYUSD"
            case cashMainnet: return "CASH"
            default: return nil
            }
        }
    }

    /// Whether `mint` is one of the well-known stablecoin mint addresses
    /// whose token program is hardcoded. Returning `false` for an arbitrary
    /// mint means callers must do an on-chain mint-owner lookup to find the
    /// program — and, for the charge client, that an unknown Token-2022 mint
    /// (which can carry transfer hooks) is gated behind an explicit opt-in.
    /// Mirrors rust `protocol::solana::is_known_stablecoin_mint`.
    ///
    /// Matches on the raw mint address only (the audit #26 gate reasons about
    /// the resolved mint, not the symbol form).
    public static func isKnownStablecoinMint(_ mint: String) -> Bool {
        switch mint {
        case usdcMainnet, usdcDevnet,
             usdtMainnet,
             usdgMainnet, usdgDevnet,
             pyusdMainnet, pyusdDevnet,
             cashMainnet:
            return true
        default:
            return false
        }
    }

    /// True if a stablecoin (by symbol or mint) uses SPL Token-2022.
    /// Mirrors rust `stablecoin_uses_token_2022`.
    public static func usesToken2022(_ currencyOrMint: String) -> Bool {
        switch stablecoinSymbol(currencyOrMint) {
        case "USDG", "PYUSD", "CASH": return true
        default: return false
        }
    }

    /// Default token program id for a currency or mint, resolving the mint
    /// first so symbols and addresses agree. Mirrors rust
    /// `default_token_program_for_currency`: Token-2022 mints (USDG, PYUSD,
    /// CASH) get the Token-2022 program; everything else the legacy program.
    public static func defaultTokenProgram(currency: String, cluster: String?) -> String {
        let mint = resolveMint(currency: currency, cluster: cluster) ?? currency
        return usesToken2022(mint) ? token2022Program : tokenProgram
    }
}
