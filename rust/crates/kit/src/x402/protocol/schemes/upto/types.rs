//! Wire types for the x402 `upto` scheme on Solana.
//!
//! `upto` authorizes a **maximum** amount; the server settles for the **actual**
//! usage (`actual ≤ max`) determined after the resource is consumed. The v1 SVM
//! backend is the `payment-channel` asset transfer method: the client opens a
//! channel whose `deposit` is the ceiling, and the operator settles the metered
//! amount with a single voucher, refunding the remainder. See
//! `specs/schemes/upto/scheme_upto_svm.md`.

use serde::{Deserialize, Serialize};

use crate::x402::error::Error;
use crate::x402::protocol::schemes::exact::ResourceInfo;

/// `upto` scheme identifier.
pub const UPTO_SCHEME: &str = "upto";

/// Payment-channel asset transfer method (normative v1).
pub const UPTO_ASSET_TRANSFER_METHOD: &str = "payment-channel";

fn upto_scheme() -> String {
    UPTO_SCHEME.to_string()
}

/// The `extra` object on an `upto` requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UptoExtra {
    /// Asset transfer method for this `upto` requirement — EVM uses `"permit2"`,
    /// SVM uses `"payment-channel"`.
    pub asset_transfer_method: String,

    /// Token program address (legacy SPL or Token-2022).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_program: Option<String>,

    /// Base58 facilitator/operator key authorized to settle (and the channel's
    /// on-chain payee + fee payer). Mirrors EVM upto's `extra.facilitatorAddress`.
    pub facilitator_address: String,

    /// Facilitator's cut in basis points (0–10000) of the settled amount; the
    /// beneficiary (`payTo`) receives `10000 - facilitatorFee`. Omitted when 0.
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub facilitator_fee: u16,

    /// Channel program id; defaults to the canonical deployment when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_program: Option<String>,

    /// Server-prefetched recent blockhash for building the open transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,

    /// Last block height at which `recent_blockhash` is valid (decimal string),
    /// bounding the open transaction's validity window. See
    /// x402-foundation/x402#2693.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_valid_block_height: Option<String>,

    /// Earliest activation time (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_after: Option<i64>,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

/// An `upto` payment requirement (the `accepted` object in a 402 challenge).
///
/// `amount` is **phase-dependent**: the authorized maximum during verification,
/// the actual charge during settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UptoRequirements {
    #[serde(default = "upto_scheme")]
    pub scheme: String,

    /// CAIP-2 network identifier.
    pub network: String,

    /// Maximum authorized amount (base units) at verification.
    pub amount: String,

    /// SPL mint address (or a known symbol like `"USDC"`).
    pub asset: String,

    /// Base58 recipient.
    pub pay_to: String,

    /// Completion window in seconds.
    pub max_timeout_seconds: u64,

    /// Scheme-specific data.
    pub extra: UptoExtra,
}

impl UptoRequirements {
    /// Parse the authorized maximum as base units.
    pub fn max_amount(&self) -> Result<u64, Error> {
        self.amount
            .parse()
            .map_err(|_| Error::Other(format!("invalid upto amount: {}", self.amount)))
    }

    /// Canonical accepted-object JSON for this requirement.
    pub fn to_accepted_value(&self) -> Result<serde_json::Value, Error> {
        serde_json::to_value(self)
            .map_err(|e| Error::Other(format!("upto requirement serialization failed: {e}")))
    }
}

/// The `PAYMENT-REQUIRED` envelope for an `upto` challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UptoRequiredEnvelope {
    pub x402_version: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,

    #[serde(default)]
    pub accepts: Vec<UptoRequirements>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The client authorization carried in `PAYMENT-SIGNATURE.payload`.
///
/// For the `payment-channel` asset transfer method the channel `open` is the
/// authorization: the client's signature commits the deposit ceiling, payee,
/// and mint. The operator settles the actual amount with a voucher it signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UptoPayload {
    /// Payer wallet (base58).
    pub from: String,

    /// Signed ceiling (base units). MUST equal verification-phase `amount`.
    pub max_amount: String,

    /// Deadline (Unix seconds); signed into the on-chain voucher.
    pub expires_at: i64,

    /// Activation time (Unix seconds).
    pub valid_after: i64,

    /// Unique per-authorization identifier.
    pub nonce: String,

    /// Channel PDA (base58).
    pub channel_id: String,

    /// On-chain escrow ceiling (base units); MUST equal `max_amount`.
    pub deposit: String,

    /// Voucher signer — the operator/facilitator key (base58).
    pub authorized_signer: String,

    /// Base64 client-signed `open` transaction for the operator to co-sign
    /// (fee payer + `rentPayer`) and broadcast. v1 is **pull-only**: the client
    /// never broadcasts `open` itself, so it needs no SOL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_transaction: Option<String>,
}

impl UptoPayload {
    /// Parse the signed ceiling as base units.
    pub fn max_amount(&self) -> Result<u64, Error> {
        self.max_amount
            .parse()
            .map_err(|_| Error::Other(format!("invalid upto maxAmount: {}", self.max_amount)))
    }

    /// Parse the deposit as base units.
    pub fn deposit(&self) -> Result<u64, Error> {
        self.deposit
            .parse()
            .map_err(|_| Error::Other(format!("invalid upto deposit: {}", self.deposit)))
    }
}

/// The `PAYMENT-SIGNATURE` envelope for an `upto` payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UptoSignatureEnvelope {
    pub x402_version: u64,

    /// The chosen `PaymentRequirements` (x402 v2 spec §5.2). Required — this is
    /// where `scheme` and `network` live; the canonical `PaymentPayload` has no
    /// envelope-level scheme/network.
    ///
    /// Kept as opaque JSON rather than a typed `UptoRequirements` so a
    /// canonical-compatible client that echoes an `accepted` object omitting
    /// fields the server never reads still parses; the server pulls `scheme`
    /// and `network` from it.
    pub accepted: serde_json::Value,

    pub payload: UptoPayload,
}

/// The `PAYMENT-RESPONSE` settlement result for an `upto` payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UptoSettlementResponse {
    pub success: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,

    /// Settlement transaction signature.
    pub transaction: String,

    pub network: String,

    /// Actual base units charged (may be `0`).
    pub amount: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements() -> UptoRequirements {
        UptoRequirements {
            scheme: UPTO_SCHEME.to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "1000000".to_string(),
            asset: "USDC".to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 300,
            extra: UptoExtra {
                asset_transfer_method: UPTO_ASSET_TRANSFER_METHOD.to_string(),
                token_program: None,
                facilitator_address: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
                facilitator_fee: 0,
                channel_program: None,
                recent_blockhash: None,
                last_valid_block_height: None,
                valid_after: None,
            },
        }
    }

    #[test]
    fn requirements_round_trip_canonical_shape() {
        let req = requirements();
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["scheme"], "upto");
        assert_eq!(json["payTo"], req.pay_to);
        assert_eq!(json["amount"], "1000000");
        assert_eq!(json["maxTimeoutSeconds"], 300);
        assert_eq!(json["extra"]["assetTransferMethod"], "payment-channel");
        assert_eq!(
            json["extra"]["facilitatorAddress"],
            req.extra.facilitator_address
        );

        let back: UptoRequirements = serde_json::from_value(json).unwrap();
        assert_eq!(back.max_amount().unwrap(), 1_000_000);
        assert_eq!(back.scheme, "upto");
    }

    #[test]
    fn payload_omits_optional_fields_and_parses_amounts() {
        let payload = UptoPayload {
            from: "Payer1111111111111111111111111111111111111".to_string(),
            max_amount: "1000000".to_string(),
            expires_at: 4_102_444_800,
            valid_after: 0,
            nonce: "n-1".to_string(),
            channel_id: "Chan1111111111111111111111111111111111111".to_string(),
            deposit: "1000000".to_string(),
            authorized_signer: "Op11111111111111111111111111111111111111111".to_string(),
            open_transaction: Some("base64tx".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"openTransaction\":\"base64tx\""));
        assert!(!json.contains("\"signature\""));
        assert_eq!(payload.max_amount().unwrap(), 1_000_000);
        assert_eq!(payload.deposit().unwrap(), 1_000_000);
    }

    #[test]
    fn parses_canonical_envelope_without_top_level_scheme() {
        // The canonical x402 v2 client (the TS playground via `@x402/core`)
        // emits `{ x402Version, payload, accepted }` with no top-level `scheme`
        // or `network`; the asset transfer method lives in `accepted.extra`.
        // Assert Rust accepts that canonical shape directly.
        let req = requirements();
        let canonical = serde_json::json!({
            "x402Version": 2,
            "payload": {
                "from": "Payer1111111111111111111111111111111111111",
                "maxAmount": "1000000",
                "expiresAt": 4_102_444_800i64,
                "validAfter": 0,
                "nonce": "n-1",
                "channelId": "Chan1111111111111111111111111111111111111",
                "deposit": "1000000",
                "authorizedSigner": "Op11111111111111111111111111111111111111111",
                "openTransaction": "base64tx",
            },
            // canonical extras we must tolerate (ignored)
            "resource": "https://example.com/x",
            "extensions": {},
            "accepted": serde_json::to_value(&req).unwrap(),
        });

        let env: UptoSignatureEnvelope = serde_json::from_value(canonical).unwrap();
        // scheme + network live in `accepted`, per x402 v2 spec §5.2.
        assert_eq!(
            env.accepted.get("network").and_then(|n| n.as_str()),
            Some(req.network.as_str()),
            "network read from accepted"
        );
        assert_eq!(
            env.accepted.get("scheme").and_then(|s| s.as_str()),
            Some("upto")
        );
        assert_eq!(
            env.payload.channel_id,
            "Chan1111111111111111111111111111111111111"
        );

        // The emitted wire shape carries no envelope-level scheme/network.
        let wire = serde_json::to_value(&env).unwrap();
        assert!(
            wire.get("scheme").is_none(),
            "no envelope-level scheme on the wire"
        );
        assert!(
            wire.get("network").is_none(),
            "no envelope-level network on the wire"
        );
        assert!(
            wire.get("accepted").is_some(),
            "accepted present on the wire"
        );
    }

    #[test]
    fn settlement_response_omits_none() {
        let resp = UptoSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some("Payer".to_string()),
            transaction: "sig".to_string(),
            network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1".to_string(),
            amount: "500000".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("errorReason"));
        assert!(json.contains("\"amount\":\"500000\""));
    }
}
