//! Solana-specific types for the charge intent.

use serde::{Deserialize, Serialize};

/// Well-known program addresses.
pub mod programs {
    pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    pub const ASSOCIATED_TOKEN_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
    pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";
    pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
    pub const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
}

/// Well-known stablecoin mint addresses.
pub mod mints {
    pub const USDC_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    pub const USDC_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
    pub const USDC_TESTNET: &str = USDC_DEVNET;
    pub const USDT_MAINNET: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
    pub const USDG_MAINNET: &str = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH";
    pub const USDG_DEVNET: &str = "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7";
    pub const USDG_TESTNET: &str = USDG_DEVNET;
    pub const PYUSD_MAINNET: &str = "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo";
    pub const PYUSD_DEVNET: &str = "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM";
    pub const PYUSD_TESTNET: &str = PYUSD_DEVNET;
    pub const CASH_MAINNET: &str = "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH";
}

/// Default RPC URLs per network.
pub fn default_rpc_url(network: &str) -> &'static str {
    match network {
        "devnet" => "https://api.devnet.solana.com",
        "localnet" => "http://localhost:8899",
        _ => "https://api.mainnet-beta.solana.com",
    }
}

/// Resolve a stablecoin symbol to a mint address for a network.
///
/// Returns `None` for native SOL and passes through unknown symbols/mints.
pub fn resolve_stablecoin_mint<'a>(currency: &'a str, network: Option<&str>) -> Option<&'a str> {
    match currency.to_uppercase().as_str() {
        "SOL" => None,
        "USDC" => Some(match network {
            Some("devnet") => mints::USDC_DEVNET,
            Some("testnet") => mints::USDC_TESTNET,
            _ => mints::USDC_MAINNET,
        }),
        "USDT" => Some(mints::USDT_MAINNET),
        "USDG" => Some(match network {
            Some("devnet") => mints::USDG_DEVNET,
            Some("testnet") => mints::USDG_TESTNET,
            _ => mints::USDG_MAINNET,
        }),
        "PYUSD" => Some(match network {
            Some("devnet") => mints::PYUSD_DEVNET,
            Some("testnet") => mints::PYUSD_TESTNET,
            _ => mints::PYUSD_MAINNET,
        }),
        "CASH" => Some(mints::CASH_MAINNET),
        _ => Some(currency),
    }
}

fn stablecoin_uses_token_2022(mint: &str) -> bool {
    matches!(
        mint,
        mints::PYUSD_MAINNET
            | mints::PYUSD_DEVNET
            | mints::USDG_MAINNET
            | mints::USDG_DEVNET
            | mints::CASH_MAINNET
    )
}

/// Default token program for a currency or mint.
pub fn default_token_program_for_currency(currency: &str, network: Option<&str>) -> &'static str {
    match resolve_stablecoin_mint(currency, network) {
        Some(mint) if stablecoin_uses_token_2022(mint) => programs::TOKEN_2022_PROGRAM,
        _ => programs::TOKEN_PROGRAM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rpc_url_devnet() {
        assert_eq!(default_rpc_url("devnet"), "https://api.devnet.solana.com");
    }

    #[test]
    fn default_rpc_url_localnet() {
        assert_eq!(default_rpc_url("localnet"), "http://localhost:8899");
    }

    #[test]
    fn default_rpc_url_mainnet() {
        assert_eq!(
            default_rpc_url("mainnet"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    #[test]
    fn default_rpc_url_unknown_defaults_to_mainnet() {
        assert_eq!(
            default_rpc_url("testnet"),
            "https://api.mainnet-beta.solana.com"
        );
        assert_eq!(default_rpc_url(""), "https://api.mainnet-beta.solana.com");
        assert_eq!(
            default_rpc_url("anything"),
            "https://api.mainnet-beta.solana.com"
        );
    }

    // ── programs module constants ──

    #[test]
    fn program_constants_are_valid_pubkeys() {
        use solana_pubkey::Pubkey;
        use std::str::FromStr;

        assert!(Pubkey::from_str(programs::TOKEN_PROGRAM).is_ok());
        assert!(Pubkey::from_str(programs::TOKEN_2022_PROGRAM).is_ok());
        assert!(Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM).is_ok());
        assert!(Pubkey::from_str(programs::COMPUTE_BUDGET_PROGRAM).is_ok());
        assert!(Pubkey::from_str(programs::MEMO_PROGRAM).is_ok());
        assert!(Pubkey::from_str(programs::SYSTEM_PROGRAM).is_ok());
    }

    #[test]
    fn program_constants_are_distinct() {
        let all = [
            programs::TOKEN_PROGRAM,
            programs::TOKEN_2022_PROGRAM,
            programs::ASSOCIATED_TOKEN_PROGRAM,
            programs::COMPUTE_BUDGET_PROGRAM,
            programs::MEMO_PROGRAM,
            programs::SYSTEM_PROGRAM,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "Programs at index {i} and {j} should differ");
                }
            }
        }
    }

    #[test]
    fn stablecoin_mint_constants_are_valid_pubkeys() {
        use solana_pubkey::Pubkey;
        use std::str::FromStr;

        assert!(Pubkey::from_str(mints::USDC_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::USDC_DEVNET).is_ok());
        assert!(Pubkey::from_str(mints::USDT_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::USDG_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::USDG_DEVNET).is_ok());
        assert!(Pubkey::from_str(mints::PYUSD_MAINNET).is_ok());
        assert!(Pubkey::from_str(mints::PYUSD_DEVNET).is_ok());
        assert!(Pubkey::from_str(mints::CASH_MAINNET).is_ok());
    }

    #[test]
    fn resolve_stablecoin_mints_by_network() {
        assert_eq!(resolve_stablecoin_mint("SOL", None), None);
        assert_eq!(
            resolve_stablecoin_mint("USDC", None),
            Some(mints::USDC_MAINNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("USDC", Some("devnet")),
            Some(mints::USDC_DEVNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("USDT", None),
            Some(mints::USDT_MAINNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("USDG", None),
            Some(mints::USDG_MAINNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("USDG", Some("devnet")),
            Some(mints::USDG_DEVNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("PYUSD", Some("devnet")),
            Some(mints::PYUSD_DEVNET)
        );
        assert_eq!(
            resolve_stablecoin_mint("CASH", None),
            Some(mints::CASH_MAINNET)
        );
        assert_eq!(resolve_stablecoin_mint("custom", None), Some("custom"));
    }

    #[test]
    fn stablecoins_default_to_correct_token_program() {
        assert_eq!(
            default_token_program_for_currency("CASH", None),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency(mints::CASH_MAINNET, None),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("PYUSD", Some("devnet")),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency(mints::PYUSD_MAINNET, None),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("USDG", Some("devnet")),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency(mints::USDG_MAINNET, None),
            programs::TOKEN_2022_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("USDC", None),
            programs::TOKEN_PROGRAM
        );
        assert_eq!(
            default_token_program_for_currency("USDT", None),
            programs::TOKEN_PROGRAM
        );
    }

    // ── MethodDetails serde ──

    #[test]
    fn method_details_default() {
        let md = MethodDetails::default();
        assert!(md.network.is_none());
        assert!(md.decimals.is_none());
        assert!(md.token_program.is_none());
        assert!(md.fee_payer.is_none());
        assert!(md.fee_payer_key.is_none());
        assert!(md.splits.is_none());
        assert!(md.recent_blockhash.is_none());
    }

    #[test]
    fn method_details_serialization_roundtrip() {
        let md = MethodDetails {
            network: Some("devnet".to_string()),
            decimals: Some(6),
            token_program: Some(programs::TOKEN_PROGRAM.to_string()),
            fee_payer: Some(true),
            fee_payer_key: Some("SomeKey123".to_string()),
            splits: Some(vec![Split {
                recipient: "Recipient1".to_string(),
                amount: "100".to_string(),
                ata_creation_required: Some(true),
                label: None,
                memo: Some("test memo".to_string()),
            }]),
            recent_blockhash: Some("BlockhashXyz".to_string()),
        };
        let json = serde_json::to_string(&md).unwrap();
        let deserialized: MethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.network.as_deref(), Some("devnet"));
        assert_eq!(deserialized.decimals, Some(6));
        assert_eq!(deserialized.fee_payer, Some(true));
        assert_eq!(deserialized.splits.as_ref().unwrap().len(), 1);
        assert_eq!(
            deserialized.splits.as_ref().unwrap()[0].ata_creation_required,
            Some(true)
        );
        assert_eq!(
            deserialized.splits.as_ref().unwrap()[0].memo.as_deref(),
            Some("test memo")
        );
    }

    #[test]
    fn method_details_omits_none_fields() {
        let md = MethodDetails::default();
        let json = serde_json::to_string(&md).unwrap();
        assert_eq!(json, "{}");
    }

    // ── CredentialPayload serde ──

    #[test]
    fn credential_payload_transaction_serde() {
        let cp = CredentialPayload::Transaction {
            transaction: "base64data".to_string(),
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(json.contains("\"transaction\":\"base64data\""));
        let deserialized: CredentialPayload = serde_json::from_str(&json).unwrap();
        match deserialized {
            CredentialPayload::Transaction { transaction } => {
                assert_eq!(transaction, "base64data");
            }
            _ => panic!("Expected Transaction variant"),
        }
    }

    #[test]
    fn credential_payload_signature_serde() {
        let cp = CredentialPayload::Signature {
            signature: "sig123".to_string(),
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"type\":\"signature\""));
        assert!(json.contains("\"signature\":\"sig123\""));
        let deserialized: CredentialPayload = serde_json::from_str(&json).unwrap();
        match deserialized {
            CredentialPayload::Signature { signature } => {
                assert_eq!(signature, "sig123");
            }
            _ => panic!("Expected Signature variant"),
        }
    }

    // ── Split serde ──

    #[test]
    fn split_serde_with_memo() {
        let split = Split {
            recipient: "R1".to_string(),
            amount: "500".to_string(),
            ata_creation_required: None,
            label: None,
            memo: Some("tip".to_string()),
        };
        let json = serde_json::to_string(&split).unwrap();
        assert!(json.contains("\"memo\":\"tip\""));
        let deserialized: Split = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.memo.as_deref(), Some("tip"));
    }

    #[test]
    fn split_serde_without_memo() {
        let split = Split {
            recipient: "R1".to_string(),
            amount: "500".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        };
        let json = serde_json::to_string(&split).unwrap();
        assert!(!json.contains("memo"));
    }

    #[test]
    fn split_serde_with_ata_creation_required() {
        let split = Split {
            recipient: "R1".to_string(),
            amount: "500".to_string(),
            ata_creation_required: Some(true),
            label: None,
            memo: None,
        };
        let json = serde_json::to_string(&split).unwrap();
        assert!(json.contains("\"ataCreationRequired\":true"));
        let deserialized: Split = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.ata_creation_required, Some(true));
    }
}

/// Solana-specific method details in the challenge request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_program: Option<String>,

    /// If true, server pays transaction fees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,

    /// Server's fee payer public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer_key: Option<String>,

    /// Additional payment splits (max 8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub splits: Option<Vec<Split>>,

    /// Server-provided recent blockhash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,
}

/// A payment split — additional transfer in the same asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Split {
    /// Base58-encoded recipient public key.
    pub recipient: String,
    /// Amount in base units.
    pub amount: String,
    /// Whether this split recipient ATA must be created idempotently before payment.
    #[serde(
        rename = "ataCreationRequired",
        skip_serializing_if = "Option::is_none"
    )]
    pub ata_creation_required: Option<bool>,
    /// Human-readable label for the recipient (e.g. "Vendor", "Tax Authority").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional memo (max 566 bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// Credential payload — what the client sends in the Authorization header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum CredentialPayload {
    /// Pull mode: client sends signed transaction bytes.
    #[serde(rename = "transaction")]
    Transaction {
        /// Base64-encoded serialized signed transaction.
        transaction: String,
    },
    /// Push mode: client sends confirmed signature.
    #[serde(rename = "signature")]
    Signature {
        /// Base58-encoded transaction signature.
        signature: String,
    },
}
