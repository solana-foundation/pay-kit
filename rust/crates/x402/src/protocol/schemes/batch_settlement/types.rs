//! Wire types for the x402 `batch-settlement` scheme on Solana.
//!
//! High-throughput channel payments: the client deposits once into an escrow
//! channel, signs cumulative Ed25519 vouchers per request (verified off-chain
//! and served immediately), and the operator redeems the latest voucher per
//! channel on-chain later, in batches. The on-chain backing is the
//! payment-channels program + 48-byte voucher shared with `upto`; the channel /
//! voucher / store logic is the wire-agnostic core also used by the MPP
//! `session` intent. See `specs/schemes/batch-settlement/scheme_batch_settlement_svm.md`.

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::protocol::schemes::exact::ResourceInfo;

/// `batch-settlement` scheme identifier.
pub const BATCH_SETTLEMENT_SCHEME: &str = "batch-settlement";

/// The only v1 settlement profile (escrow payment channel).
pub const PROFILE_PAYMENT_CHANNEL: &str = "payment-channel";

fn batch_scheme() -> String {
    BATCH_SETTLEMENT_SCHEME.to_string()
}

/// A distribution split committed at channel open.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSplit {
    pub recipient: String,
    pub share_bps: u16,
}

/// The `extra` object on a `batch-settlement` requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchExtra {
    /// Settlement profiles the server supports, in preference order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,

    /// Channel program id (base58).
    pub channel_program: String,

    /// Forced-close grace period (seconds, non-zero).
    pub grace_period_seconds: u32,

    /// Token decimals.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,

    /// Token program address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_program: Option<String>,

    /// Operator key that co-signs/sponsors `open` + submits settlement (base58).
    pub facilitator: String,

    /// Server-prefetched recent blockhash for building `open`/`topUp`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,

    /// Suggested initial deposit (base units).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_deposit: Option<String>,

    /// HTTP-enforced minimum initial deposit (base units).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_deposit: Option<String>,

    /// Minimum cumulative increment between accepted vouchers (base units).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,

    /// Merchant-side splits committed at open; payee gets the remainder.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distribution_splits: Vec<BatchSplit>,
}

/// A `batch-settlement` payment requirement (the `accepted` object in a 402).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchRequirements {
    #[serde(default = "batch_scheme")]
    pub scheme: String,

    /// CAIP-2 network identifier.
    pub network: String,

    /// Per-request price (base units).
    pub amount: String,

    /// SPL mint address (or a known symbol like `"USDC"`).
    pub asset: String,

    /// Base58 channel payee.
    pub pay_to: String,

    /// Completion window in seconds.
    pub max_timeout_seconds: u64,

    pub extra: BatchExtra,
}

impl BatchRequirements {
    /// Parse the per-request price as base units.
    pub fn amount(&self) -> Result<u64, Error> {
        self.amount
            .parse()
            .map_err(|_| Error::Other(format!("invalid batch amount: {}", self.amount)))
    }

    /// Canonical accepted-object JSON for this requirement.
    pub fn to_accepted_value(&self) -> Result<serde_json::Value, Error> {
        serde_json::to_value(self)
            .map_err(|e| Error::Other(format!("batch requirement serialization failed: {e}")))
    }
}

/// The `PAYMENT-REQUIRED` envelope for a `batch-settlement` challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchRequiredEnvelope {
    pub x402_version: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,

    #[serde(default)]
    pub accepts: Vec<BatchRequirements>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A signed cumulative voucher (the off-chain authorization).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVoucher {
    pub channel_id: String,
    /// Cumulative amount authorized (base units), monotonically increasing.
    pub cumulative_amount: String,
    /// Voucher expiry (Unix seconds); MUST be a future time (`0` = expired).
    pub expires_at: i64,
    /// Base58 voucher signer (the channel's `authorizedSigner`).
    pub signer: String,
    /// Base58 Ed25519 signature over the 48-byte voucher payload.
    pub signature: String,
}

impl BatchVoucher {
    pub fn cumulative(&self) -> Result<u64, Error> {
        self.cumulative_amount.parse().map_err(|_| {
            Error::Other(format!(
                "invalid cumulativeAmount: {}",
                self.cumulative_amount
            ))
        })
    }
}

/// Channel configuration carried in a `deposit` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchChannelConfig {
    pub payer: String,
    pub payee: String,
    pub mint: String,
    pub authorized_signer: String,
    pub salt: String,
    pub deposit_amount: String,
    pub grace_period_seconds: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distribution_splits: Vec<BatchSplit>,
}

/// The client authorization carried in `PAYMENT-SIGNATURE.payload`, a tagged
/// union on `type`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BatchPayload {
    /// Open a channel (or top up) and authorize the first/next voucher.
    Deposit {
        channel_config: BatchChannelConfig,
        /// Base64 client-signed `open`/`topUp` transaction for the operator to
        /// co-sign + broadcast.
        transaction: String,
        /// First cumulative voucher (omitted on a pure top-up).
        #[serde(skip_serializing_if = "Option::is_none")]
        voucher: Option<BatchVoucher>,
    },
    /// Steady-state paid request: a new cumulative voucher (no transaction).
    Voucher {
        channel_id: String,
        voucher: BatchVoucher,
    },
    /// Cooperative close (the application route is bypassed).
    Refund {
        channel_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        voucher: Option<BatchVoucher>,
    },
}

impl BatchPayload {
    /// The channel id this payload targets, when carried directly. `Deposit`
    /// returns `None` — its channel id is derived from `channel_config` (the
    /// PDA), not carried as a field.
    pub fn channel_id(&self) -> Option<&str> {
        match self {
            BatchPayload::Deposit { .. } => None,
            BatchPayload::Voucher { channel_id, .. } => Some(channel_id),
            BatchPayload::Refund { channel_id, .. } => Some(channel_id),
        }
    }
}

/// The `PAYMENT-SIGNATURE` envelope for a `batch-settlement` payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSignatureEnvelope {
    pub x402_version: u64,
    pub scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<serde_json::Value>,
    pub payload: BatchPayload,
}

/// On-chain channel snapshot returned in settlement responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchChannelSnapshot {
    pub channel_id: String,
    pub deposit: String,
    pub settled: String,
    /// Amount the server has swept on-chain via `distribute`. This is the
    /// server's own accounting (`"0"` until the close sweeps the pool), not a
    /// fresh read of the on-chain `paidOut`.
    pub paid_out: String,
    /// `open` | `closing` | `finalized`.
    pub status: String,
}

/// The `PAYMENT-RESPONSE` settlement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// On-chain signature (empty `""` for an off-chain voucher acceptance).
    pub transaction: String,
    pub network: String,
    /// Amount moved on-chain (`""` for voucher-only).
    pub amount: String,
    /// The per-request charge committed off-chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charged_amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_state: Option<BatchChannelSnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> BatchRequirements {
        BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "10000".to_string(),
            asset: "USDC".to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 3600,
            extra: BatchExtra {
                profiles: vec![PROFILE_PAYMENT_CHANNEL.to_string()],
                channel_program: "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc".to_string(),
                grace_period_seconds: 900,
                decimals: Some(6),
                token_program: None,
                facilitator: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
                recent_blockhash: None,
                suggested_deposit: Some("500000".to_string()),
                minimum_deposit: Some("100000".to_string()),
                min_voucher_delta: None,
                distribution_splits: vec![],
            },
        }
    }

    #[test]
    fn requirements_round_trip_canonical_shape() {
        let json = serde_json::to_value(requirements()).unwrap();
        assert_eq!(json["scheme"], "batch-settlement");
        assert_eq!(
            json["payTo"],
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        );
        assert_eq!(json["amount"], "10000");
        assert_eq!(
            json["extra"]["channelProgram"],
            "GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc"
        );
        assert_eq!(json["extra"]["gracePeriodSeconds"], 900);
        let back: BatchRequirements = serde_json::from_value(json).unwrap();
        assert_eq!(back.amount().unwrap(), 10000);
    }

    #[test]
    fn payload_union_tags_round_trip() {
        let voucher = BatchVoucher {
            channel_id: "Chan11111111111111111111111111111111111111".to_string(),
            cumulative_amount: "20000".to_string(),
            expires_at: 4_102_444_800,
            signer: "Signer1111111111111111111111111111111111111".to_string(),
            signature: "sig".to_string(),
        };
        let v = BatchPayload::Voucher {
            channel_id: "Chan11111111111111111111111111111111111111".to_string(),
            voucher: voucher.clone(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"type\":\"voucher\""));
        assert!(json.contains("\"cumulativeAmount\":\"20000\""));
        let back: BatchPayload = serde_json::from_str(&json).unwrap();
        matches!(back, BatchPayload::Voucher { .. });

        let r = BatchPayload::Refund {
            channel_id: "Chan11111111111111111111111111111111111111".to_string(),
            voucher: None,
        };
        assert!(serde_json::to_string(&r)
            .unwrap()
            .contains("\"type\":\"refund\""));
        assert_eq!(voucher.cumulative().unwrap(), 20000);
    }
}
