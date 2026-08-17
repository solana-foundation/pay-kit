//! Canonical SPL mint addresses for supported stablecoins.
//!
//! Single source of truth shared by `solana-mpp`, `solana-x402`, and downstream
//! clients. Both protocol crates re-export this module (`mpp::mints`,
//! `x402::exact::mints`) so a mint address is written in exactly one place.
//! Add new stablecoins here, not in the protocol crates.

pub const USDC_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
pub const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
pub const USDC_TESTNET: &str = USDC_DEVNET;
/// Devnet-only Token-2022 test dollar used for payment-channel integration and
/// load testing. There is intentionally no mainnet or localnet alias.
pub const USDTEST_DEVNET: &str = "6MJyWHwFpPsaTEuYarEz49ngtsSKPYn6yHqtJUW2a9St";
pub const USDT_MAINNET: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
pub const USDG_MAINNET: &str = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH";
pub const USDG_DEVNET: &str = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7";
pub const USDG_TESTNET: &str = USDG_DEVNET;
pub const PYUSD_MAINNET: &str = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
pub const PYUSD_DEVNET: &str = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM";
pub const PYUSD_TESTNET: &str = PYUSD_DEVNET;
pub const CASH_MAINNET: &str = "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH";

/// USDPT (Anchorage) — Token-2022 mint with the Confidential Transfer
/// extension enabled. Confidential-capable stablecoin used by the MPP
/// confidential charge flow.
pub const USDPT_MAINNET: &str = "HVWf8JmLoHs99Lw8Psf3fyqAtA4crWxCPkrmSdNjhNH3";
