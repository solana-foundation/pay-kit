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
///
/// Re-exported from [`solana_pay_core::mints`] — the single source of truth
/// shared with `solana-x402`. Don't add literals here; add them in core.
pub mod mints {
    pub use solana_pay_core::mints::*;
}

/// Canonical Solana network slugs per spec §7.2.
///
/// `mainnet` is the canonical form. The literal `mainnet-beta` is a Solana
/// RPC hostname convention and MUST NOT appear as a wire-format network
/// slug — `validate_network` rejects it explicitly to prevent the
/// non-canonical name from drifting back in.
pub const NETWORK_MAINNET: &str = "mainnet";
pub const NETWORK_DEVNET: &str = "devnet";
pub const NETWORK_LOCALNET: &str = "localnet";

/// Default network when callers omit it. Matches the spec's "defaults to
/// mainnet if omitted" guidance.
pub const DEFAULT_NETWORK: &str = NETWORK_MAINNET;

/// Maximum byte length of an SPL Memo instruction payload.
pub const MAX_MEMO_BYTES: usize = 566;

/// Audit #37: allowlist the network slug per spec §7.2. Rejects anything
/// that isn't `mainnet`, `devnet`, or `localnet`, so a typo or stale name
/// (e.g. `mainnet-beta`, `testnet`) surfaces at the boundary instead of
/// silently mapping to a default cluster.
pub fn validate_network(network: &str) -> Result<(), crate::error::Error> {
    match network {
        NETWORK_MAINNET | NETWORK_DEVNET | NETWORK_LOCALNET => Ok(()),
        "" => Err(crate::error::Error::InvalidConfig(
            "network must not be empty (one of `mainnet`, `devnet`, `localnet`)".into(),
        )),
        other => Err(crate::error::Error::InvalidConfig(format!(
            "Unknown network `{other}` (allowed: `mainnet`, `devnet`, `localnet`)"
        ))),
    }
}

/// Default RPC URLs per network. Inputs are expected to be canonical
/// slugs (see `validate_network`); unknown slugs fall through to the
/// mainnet RPC for backwards compatibility, but `validate_network` at
/// `Mpp::new` ensures servers can never reach the fallback path.
pub fn default_rpc_url(network: &str) -> &'static str {
    match network {
        NETWORK_DEVNET => "https://api.devnet.solana.com",
        NETWORK_LOCALNET => "http://localhost:8899",
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
        "USDPT" => Some(mints::USDPT_MAINNET),
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
            | mints::USDPT_MAINNET
    )
}

/// Whether `mint` is a well-known stablecoin whose Token-2022 mint enables the
/// Confidential Transfer extension. Only these mints may be used with
/// [`MethodDetails::confidential`] set to `true`. Arbitrary mints return
/// `false`; callers MUST confirm the `ConfidentialTransferMint` extension
/// (and its auditor) on-chain before issuing a confidential challenge.
pub fn stablecoin_supports_confidential(mint: &str) -> bool {
    matches!(mint, mints::USDPT_MAINNET)
}

/// Whether `mint` is one of the well-known stablecoin mints whose token
/// program is hardcoded. Returning `false` for an arbitrary mint means
/// callers must do an on-chain mint-owner lookup to find the program.
pub fn is_known_stablecoin_mint(mint: &str) -> bool {
    matches!(
        mint,
        mints::USDC_MAINNET
            | mints::USDC_DEVNET
            | mints::USDT_MAINNET
            | mints::USDG_MAINNET
            | mints::USDG_DEVNET
            | mints::PYUSD_MAINNET
            | mints::PYUSD_DEVNET
            | mints::CASH_MAINNET
            | mints::USDPT_MAINNET
    )
}

/// Default token program for a currency or mint.
///
/// Only valid for well-known stablecoins. Callers handling arbitrary mints
/// MUST resolve the token program via an on-chain mint-owner lookup
/// (spec §7.2) rather than relying on this fallback.
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
        assert!(md.confidential.is_none());
        assert!(md.auditor_elgamal_pubkey.is_none());
        assert!(md.recipient_elgamal_pubkey.is_none());
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
            confidential: None,
            auditor_elgamal_pubkey: None,
            recipient_elgamal_pubkey: None,
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

    // ── Audit #30: checked_sum_split_amounts ──

    fn split_with_amount(amt: &str) -> Split {
        Split {
            recipient: "R".to_string(),
            amount: amt.to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }
    }

    #[test]
    fn checked_sum_split_amounts_within_u64_sums_correctly() {
        let splits = [
            split_with_amount("100"),
            split_with_amount("200"),
            split_with_amount("3"),
        ];
        assert_eq!(checked_sum_split_amounts(&splits), Some(303));
    }

    #[test]
    fn checked_sum_split_amounts_overflows_returns_none() {
        let near_max = (u64::MAX / 2) + 1;
        let splits = [
            split_with_amount(&near_max.to_string()),
            split_with_amount(&near_max.to_string()),
        ];
        // Sum would be u64::MAX + 1 — must report overflow.
        assert_eq!(checked_sum_split_amounts(&splits), None);
    }

    #[test]
    fn checked_sum_split_amounts_unparseable_treated_as_zero() {
        // Strict parseability is audit #21's concern; here we just check
        // that an unparseable amount doesn't break the arithmetic.
        let splits = [
            split_with_amount("100"),
            split_with_amount("not-a-number"),
            split_with_amount("50"),
        ];
        assert_eq!(checked_sum_split_amounts(&splits), Some(150));
    }

    #[test]
    fn checked_sum_split_amounts_empty_is_zero() {
        let splits: [Split; 0] = [];
        assert_eq!(checked_sum_split_amounts(&splits), Some(0));
    }

    // ── Audit #21: validate_splits ──

    fn split(recipient: &str, amount: &str) -> Split {
        Split {
            recipient: recipient.to_string(),
            amount: amount.to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }
    }

    fn unique_pubkey() -> String {
        solana_pubkey::Pubkey::new_unique().to_string()
    }

    #[test]
    fn validate_splits_accepts_valid_set() {
        let splits = vec![
            split(&unique_pubkey(), "100"),
            split(&unique_pubkey(), "200"),
            split(&unique_pubkey(), "300"),
        ];
        validate_splits(&splits).expect("valid splits should be accepted");
    }

    #[test]
    fn validate_splits_accepts_empty() {
        let splits: Vec<Split> = vec![];
        validate_splits(&splits).expect("empty list is allowed");
    }

    #[test]
    fn validate_splits_rejects_count_above_max() {
        let splits: Vec<Split> = (0..(MAX_SPLITS + 1))
            .map(|_| split(&unique_pubkey(), "1"))
            .collect();
        let err = validate_splits(&splits).err().expect("too many splits");
        assert!(matches!(err, crate::error::Error::TooManySplits));
    }

    #[test]
    fn validate_splits_rejects_invalid_recipient() {
        let splits = vec![split("not-a-pubkey!!", "100")];
        let err = validate_splits(&splits).err().expect("bad recipient");
        assert!(
            format!("{err}").contains("splits[0]: invalid recipient pubkey"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_splits_rejects_unparseable_amount() {
        let splits = vec![split(&unique_pubkey(), "not-a-number")];
        let err = validate_splits(&splits).err().expect("bad amount");
        assert!(
            format!("{err}").contains("is not a valid u64"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_splits_rejects_zero_amount() {
        let splits = vec![split(&unique_pubkey(), "0")];
        let err = validate_splits(&splits).err().expect("zero amount");
        assert!(
            format!("{err}").contains("amount must be greater than zero"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_splits_rejects_overflowing_aggregate() {
        let near_max = (u64::MAX / 2) + 1;
        let splits = vec![
            split(&unique_pubkey(), &near_max.to_string()),
            split(&unique_pubkey(), &near_max.to_string()),
        ];
        let err = validate_splits(&splits).err().expect("aggregate overflow");
        assert!(format!("{err}").contains("overflows u64"), "got: {err}");
    }

    #[test]
    fn validate_splits_rejects_duplicate_recipient() {
        let dup = unique_pubkey();
        let splits = vec![split(&dup, "100"), split(&dup, "200")];
        let err = validate_splits(&splits).err().expect("duplicate recipient");
        assert!(
            format!("{err}").contains("duplicate recipient"),
            "got: {err}"
        );
    }

    // ── Confidential transfers: registry ──

    #[test]
    fn usdpt_mint_constant_is_valid_pubkey() {
        use solana_pubkey::Pubkey;
        use std::str::FromStr;
        assert!(Pubkey::from_str(mints::USDPT_MAINNET).is_ok());
    }

    #[test]
    fn resolve_usdpt_symbol() {
        assert_eq!(
            resolve_stablecoin_mint("USDPT", None),
            Some(mints::USDPT_MAINNET)
        );
        // Case-insensitive, like the other symbols.
        assert_eq!(
            resolve_stablecoin_mint("usdpt", Some("mainnet")),
            Some(mints::USDPT_MAINNET)
        );
    }

    #[test]
    fn usdpt_uses_token_2022_and_is_known() {
        assert!(stablecoin_uses_token_2022(mints::USDPT_MAINNET));
        assert!(is_known_stablecoin_mint(mints::USDPT_MAINNET));
        assert_eq!(
            default_token_program_for_currency("USDPT", None),
            programs::TOKEN_2022_PROGRAM
        );
    }

    #[test]
    fn stablecoin_supports_confidential_only_for_ct_mints() {
        assert!(stablecoin_supports_confidential(mints::USDPT_MAINNET));
        // A Token-2022 stablecoin without the CT extension is not confidential.
        assert!(!stablecoin_supports_confidential(mints::CASH_MAINNET));
        // A plain SPL stablecoin is not confidential.
        assert!(!stablecoin_supports_confidential(mints::USDC_MAINNET));
        // Arbitrary mints are not confidential until confirmed on-chain.
        assert!(!stablecoin_supports_confidential(&unique_pubkey()));
    }

    // ── Confidential transfers: CredentialPayload::Bundle serde ──

    #[test]
    fn credential_payload_bundle_serde() {
        let cp = CredentialPayload::Bundle {
            transactions: vec!["txA".to_string(), "txB".to_string()],
        };
        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"type\":\"bundle\""));
        assert!(json.contains("\"transactions\":[\"txA\",\"txB\"]"));
        let deserialized: CredentialPayload = serde_json::from_str(&json).unwrap();
        match deserialized {
            CredentialPayload::Bundle { transactions } => {
                assert_eq!(transactions, vec!["txA", "txB"]);
            }
            _ => panic!("Expected Bundle variant"),
        }
    }

    // ── Confidential transfers: MethodDetails serde ──

    #[test]
    fn method_details_confidential_roundtrip() {
        let md = MethodDetails {
            decimals: Some(6),
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            confidential: Some(true),
            auditor_elgamal_pubkey: Some(
                "GCJ+UreNo+YOlsWHCswYmm7+Phb90ionwJkBsIS4OUo=".to_string(),
            ),
            recipient_elgamal_pubkey: Some("cmVjaXBpZW50LWVsZ2FtYWwtcHVibGljLWtleQ==".to_string()),
            ..MethodDetails::default()
        };
        let json = serde_json::to_string(&md).unwrap();
        assert!(json.contains("\"confidential\":true"));
        assert!(json.contains("\"auditorElgamalPubkey\""));
        assert!(json.contains("\"recipientElgamalPubkey\""));
        let back: MethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(back.confidential, Some(true));
        assert_eq!(
            back.auditor_elgamal_pubkey.as_deref(),
            Some("GCJ+UreNo+YOlsWHCswYmm7+Phb90ionwJkBsIS4OUo=")
        );
    }

    // ── Confidential transfers: validate_confidential_charge ──

    fn confidential_md() -> MethodDetails {
        MethodDetails {
            decimals: Some(6),
            token_program: Some(programs::TOKEN_2022_PROGRAM.to_string()),
            confidential: Some(true),
            auditor_elgamal_pubkey: Some("auditor-key".to_string()),
            ..MethodDetails::default()
        }
    }

    #[test]
    fn validate_confidential_noop_when_not_confidential() {
        let md = MethodDetails::default();
        validate_confidential_charge("sol", &md).expect("non-confidential is unconstrained");
    }

    #[test]
    fn validate_confidential_accepts_valid() {
        validate_confidential_charge(mints::USDPT_MAINNET, &confidential_md())
            .expect("valid confidential charge");
    }

    #[test]
    fn validate_confidential_rejects_native_sol() {
        let err = validate_confidential_charge("sol", &confidential_md())
            .err()
            .expect("sol rejected");
        assert!(format!("{err}").contains("not native SOL"), "got: {err}");
    }

    #[test]
    fn validate_confidential_rejects_wrong_token_program() {
        let mut md = confidential_md();
        md.token_program = Some(programs::TOKEN_PROGRAM.to_string());
        let err = validate_confidential_charge(mints::USDPT_MAINNET, &md)
            .err()
            .expect("legacy token program rejected");
        assert!(format!("{err}").contains("Token-2022"), "got: {err}");
    }

    #[test]
    fn validate_confidential_auditor_optional() {
        // No auditor is allowed: verification is recipient-key, and the auditor
        // is the mint issuer's optional compliance facility.
        let mut md = confidential_md();
        md.auditor_elgamal_pubkey = None;
        validate_confidential_charge(mints::USDPT_MAINNET, &md)
            .expect("missing auditor is allowed");

        // A present-but-empty auditor pubkey is malformed and rejected.
        md.auditor_elgamal_pubkey = Some(String::new());
        let err = validate_confidential_charge(mints::USDPT_MAINNET, &md)
            .err()
            .expect("empty auditor rejected");
        assert!(
            format!("{err}").contains("auditorElgamalPubkey"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_confidential_rejects_splits() {
        let mut md = confidential_md();
        md.splits = Some(vec![Split {
            recipient: unique_pubkey(),
            amount: "10".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }]);
        let err = validate_confidential_charge(mints::USDPT_MAINNET, &md)
            .err()
            .expect("splits rejected");
        assert!(format!("{err}").contains("splits"), "got: {err}");
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

    /// Additional payment splits (max `MAX_SPLITS`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub splits: Option<Vec<Split>>,

    /// Server-provided recent blockhash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,

    /// If true, the charge MUST settle as a Token-2022 confidential transfer
    /// (the amount is encrypted on-chain). Requires a Token-2022 mint with the
    /// Confidential Transfer extension, a `bundle` credential, and no `splits`.
    /// An auditor is optional (mint-issuer facility). See
    /// [`validate_confidential_charge`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidential: Option<bool>,

    /// Base64-encoded twisted-ElGamal public key of the mint's
    /// confidential-transfer auditor. Optional: the auditor is the mint issuer's
    /// compliance facility, not required for a charge (settlement is
    /// recipient-key); only validated to be non-empty when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auditor_elgamal_pubkey: Option<String>,

    /// Base64-encoded twisted-ElGamal public key of the recipient's
    /// confidential token account, supplied as a hint to save an RPC lookup.
    /// Clients MUST verify it against on-chain state before use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_elgamal_pubkey: Option<String>,
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

/// Maximum number of payment splits per challenge.
///
/// Mirrors the upper bound enforced by the TS SDK and the wire-format
/// guidance from the MPP spec. Single source of truth for both client-side
/// (pre-build) and server-side (pre-broadcast) cap checks.
pub const MAX_SPLITS: usize = 8;

/// Audit #21: validate a list of payment splits at challenge issuance.
///
/// Single source of truth for both server entry points (`charge_with_options`
/// and `charge_challenge_with_options`). Without this gate, malformed
/// splits would otherwise only surface at the chain — too late for the
/// merchant to recover and bad UX for the payer.
///
/// Checks (each callsite gets the same error shape):
/// 1. `splits.len() <= MAX_SPLITS`.
/// 2. Each `split.recipient` parses as a `Pubkey`.
/// 3. Each `split.amount` parses as `u64` AND is non-zero.
/// 4. The aggregate sum fits in `u64` (`checked_sum_split_amounts` is `Some`).
/// 5. No duplicate `recipient` across splits.
///
/// Application-level recipient allowlists are out of scope — an SDK
/// shouldn't bake in domain-specific policy.
pub fn validate_splits(splits: &[Split]) -> Result<(), crate::error::Error> {
    use crate::error::Error;
    use std::collections::HashSet;
    use std::str::FromStr;

    if splits.len() > MAX_SPLITS {
        return Err(Error::TooManySplits);
    }

    let mut seen_recipients: HashSet<&str> = HashSet::with_capacity(splits.len());
    for (idx, split) in splits.iter().enumerate() {
        solana_pubkey::Pubkey::from_str(&split.recipient).map_err(|e| {
            Error::InvalidConfig(format!("splits[{idx}]: invalid recipient pubkey: {e}"))
        })?;
        let amount = split.amount.parse::<u64>().map_err(|_| {
            Error::InvalidConfig(format!(
                "splits[{idx}]: amount `{}` is not a valid u64",
                split.amount
            ))
        })?;
        if amount == 0 {
            return Err(Error::InvalidConfig(format!(
                "splits[{idx}]: amount must be greater than zero"
            )));
        }
        if !seen_recipients.insert(split.recipient.as_str()) {
            return Err(Error::InvalidConfig(format!(
                "splits[{idx}]: duplicate recipient `{}`",
                split.recipient
            )));
        }
    }

    if checked_sum_split_amounts(splits).is_none() {
        return Err(Error::InvalidConfig(
            "Sum of split amounts overflows u64".into(),
        ));
    }

    Ok(())
}

/// Audit #30: sum split amounts in base units with overflow detection.
///
/// Returns `None` if the running total would overflow `u64`. Unparseable
/// `amount` strings are treated as 0 — strict parseability is audit #21's
/// concern; here we only address the *arithmetic* overflow shape so a
/// stuffed split list cannot panic (debug) or wrap (release) downstream
/// callers that derive the primary amount via `total - splits_total`.
pub fn checked_sum_split_amounts(splits: &[Split]) -> Option<u64> {
    splits
        .iter()
        .map(|s| s.amount.parse::<u64>().unwrap_or(0))
        .try_fold(0u64, |acc, x| acc.checked_add(x))
}

/// Validate the confidential-charge constraints from the Solana charge spec.
///
/// A no-op when `md.confidential` is not `Some(true)`. Otherwise enforces, per
/// the spec's confidential profile:
/// 1. `currency` is an SPL mint, not native SOL.
/// 2. `token_program`, if declared, is the Token-2022 program.
/// 3. `auditor_elgamal_pubkey`, if present, is non-empty. The auditor is the
///    mint issuer's optional compliance facility, NOT required for a charge —
///    the payee verifies the amount it received with its own recipient key.
/// 4. No `splits` (combining confidential transfers with splits is out of
///    scope for `draft-00`).
///
/// This is the single source of truth for both the server (challenge
/// issuance) and the client (challenge verification before building the
/// bundle).
pub fn validate_confidential_charge(
    currency: &str,
    md: &MethodDetails,
) -> Result<(), crate::error::Error> {
    use crate::error::Error;

    if !md.confidential.unwrap_or(false) {
        return Ok(());
    }

    if currency.eq_ignore_ascii_case("sol") {
        return Err(Error::InvalidConfig(
            "confidential transfers require an SPL Token-2022 mint, not native SOL".into(),
        ));
    }

    if let Some(tp) = md.token_program.as_deref() {
        if tp != programs::TOKEN_2022_PROGRAM {
            return Err(Error::InvalidConfig(
                "confidential transfers require the Token-2022 program".into(),
            ));
        }
    }

    // The auditor key is the mint issuer's optional compliance facility — NOT
    // required for a charge (the payee verifies the amount it received with its
    // own recipient key). Only reject a present-but-empty value as malformed.
    if matches!(md.auditor_elgamal_pubkey.as_deref(), Some("")) {
        return Err(Error::InvalidConfig(
            "auditorElgamalPubkey, when present, must not be empty".into(),
        ));
    }

    if md.splits.as_ref().is_some_and(|s| !s.is_empty()) {
        return Err(Error::InvalidConfig(
            "confidential transfers cannot be combined with splits".into(),
        ));
    }

    Ok(())
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
    /// Confidential mode: client sends an ordered bundle of signed
    /// transactions (proof-context setup, the confidential transfer, and
    /// context-account cleanup). The server submits them sequentially. Used
    /// only when `MethodDetails.confidential` is `true`.
    #[serde(rename = "bundle")]
    Bundle {
        /// Ordered, non-empty list of base64-encoded serialized signed
        /// transactions. The final element MUST contain the confidential
        /// transfer instruction.
        transactions: Vec<String>,
    },
}
