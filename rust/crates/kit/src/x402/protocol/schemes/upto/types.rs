//! Wire types for the x402 `upto` scheme on Solana.
//!
//! `upto` authorizes a **maximum** amount; the server settles for the **actual**
//! usage (`actual <= max`) determined after the resource is consumed. On Solana
//! the client opens a payment channel whose `deposit` is the ceiling, and the
//! fee payer (the channel's zero-share payee) settles the metered amount with
//! a single receiver-authorizer voucher, refunding the remainder. See
//! `specs/schemes/upto/scheme_upto_svm.md`.

use serde::{Deserialize, Serialize};

use crate::x402::error::Error;
use crate::x402::protocol::schemes::exact::ResourceInfo;

/// `upto` scheme identifier.
pub const UPTO_SCHEME: &str = "upto";

fn upto_scheme() -> String {
    UPTO_SCHEME.to_string()
}

/// The `extra` object on an `upto` requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UptoExtra {
    /// Token program address (legacy SPL or Token-2022).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_program: Option<String>,

    /// Base58 key that sponsors the transaction fee and channel rent and holds
    /// the zero-share channel payee seat (lifecycle authority: it signs
    /// `settle_and_seal` and can seal with `has_voucher = 0` to recover rent,
    /// but cannot settle a nonzero amount or redirect funds).
    pub fee_payer: String,

    /// Base58 voucher signer (the channel's `authorized_signer`).
    pub receiver_authorizer: String,

    /// Transaction message versions the server accepts (`0`, `1`). Absent
    /// means `[0]`. See `core::tx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_versions: Option<Vec<crate::core::tx::TxVersion>>,

    /// Channel forced-close delay, in seconds.
    pub withdraw_delay: u32,

    /// Server-prefetched recent blockhash for building the open transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,

    /// Last block height at which `recent_blockhash` is valid (decimal string),
    /// bounding the open transaction's validity window. See
    /// x402-foundation/x402#2693.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_valid_block_height: Option<String>,

    /// Server-prefetched current slot, analogous to `recentBlockhash`. Feeds
    /// the program's `openSlot` — a channel-PDA seed; the program rejects
    /// opens whose slot falls outside its window. Typed `number` by the
    /// scheme's §4.1 table; the decimal-string form other SDKs emit is read
    /// too (see [`Slot`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_slot: Option<Slot>,

    /// Earliest activation time (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_after: Option<i64>,

    /// Seller-declared memo the client must emit as a single SPL Memo
    /// instruction after `open`. Absent means the client is free to emit its
    /// own memo (or none at all).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
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

/// A slot (`u64`). The scheme types `openSlot` and `extra.recentSlot` as
/// JSON numbers (scheme_upto_svm.md §4.1, §4.2); every other SDK emits the
/// decimal-string form, which is read too (RULINGS.md U1: a verifier that
/// accepts the string form is not in breach). Anything else — a sign,
/// whitespace, a fraction, a value over `u64::MAX` — is refused when parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slot(u64);

impl Slot {
    pub const fn new(slot: u64) -> Self {
        Self(slot)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for Slot {
    fn from(slot: u64) -> Self {
        Self(slot)
    }
}

impl std::fmt::Display for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Slot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // RULINGS.md U1: the producer form is still open upstream; every
        // other SDK requires the decimal string.
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Slot {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        slot_from_value(&value).map(Self).ok_or_else(|| {
            serde::de::Error::custom(format!("invalid payload: slot {value} is not a u64"))
        })
    }
}

fn slot_from_value(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => decimal_u64(s),
        _ => None,
    }
}

/// A non-empty run of ASCII digits that fits in a `u64` (no sign, no
/// whitespace: `u64::from_str` alone would take `"+5"`).
fn decimal_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// The channel salt: a `u64` carried as a decimal string (§4.2 “Unique
/// decimal u64 salt”). Parsed once at the boundary, so the open binding
/// compares integers, never text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UptoNonce(u64);

impl UptoNonce {
    pub const fn new(salt: u64) -> Self {
        Self(salt)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for UptoNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for UptoNonce {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

/// The client authorization carried in `PAYMENT-SIGNATURE.payload`.
///
/// The channel `open` is the authorization: the client's signature commits the
/// deposit ceiling, payee, and mint. The fee payer settles the actual amount
/// carrying a voucher the receiver authorizer signs.
///
/// Deserializing is the scheme's Phase 3 step 0: a payload carrying the
/// claim-only `voucherSignature` or the per-settle `type` (present at all,
/// even empty or `null`) does not parse, so no verifier can admit one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", try_from = "RawUptoPayload")]
pub struct UptoPayload {
    /// Payer wallet (base58).
    pub from: String,

    /// Signed ceiling (base units). MUST equal verification-phase `amount`.
    pub max_amount: String,

    /// Deadline (Unix seconds); signed into the on-chain voucher.
    pub expires_at: i64,

    /// Activation time (Unix seconds).
    pub valid_after: i64,

    /// Channel salt used by the open instruction.
    pub nonce: UptoNonce,

    /// Channel PDA (base58).
    pub channel_id: String,

    /// On-chain escrow ceiling (base units); MUST equal `max_amount`.
    pub deposit: String,

    /// Voucher signer — the receiver authorizer key (base58).
    pub authorized_signer: String,

    /// Channel open slot used by the open instruction.
    pub open_slot: Slot,

    /// Base64 client-signed `open` transaction for the fee payer to co-sign
    /// (fee payer + `rentPayer`) and broadcast. v1 is **pull-only**: the client
    /// never broadcasts `open` itself, so it needs no SOL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_transaction: Option<String>,
}

/// Error code for a client payload carrying `voucherSignature` (Phase 3 step 0).
pub const ERR_UNEXPECTED_VOUCHER: &str = "invalid_upto_svm_payload_unexpected_voucher";

/// Error code for a client payload carrying `type` (Phase 3 step 0).
pub const ERR_PAYLOAD_TYPE: &str = "invalid_upto_svm_payload_type";

/// The wire shape [`UptoPayload`] is parsed from.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUptoPayload {
    from: String,
    max_amount: String,
    expires_at: i64,
    valid_after: i64,
    nonce: serde_json::Value,
    channel_id: String,
    deposit: String,
    authorized_signer: String,
    open_slot: serde_json::Value,
    #[serde(default)]
    open_transaction: Option<String>,
    #[serde(default, deserialize_with = "present")]
    voucher_signature: Option<serde_json::Value>,
    #[serde(default, rename = "type", deserialize_with = "present")]
    settle_type: Option<serde_json::Value>,
}

/// `Some` whenever the key is present, `null` included.
fn present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

impl TryFrom<RawUptoPayload> for UptoPayload {
    type Error = String;

    fn try_from(raw: RawUptoPayload) -> Result<Self, Self::Error> {
        if raw.voucher_signature.is_some() {
            return Err(format!(
                "{ERR_UNEXPECTED_VOUCHER}: voucherSignature is claim-only and server-owned; \
                 a client payload must not carry it"
            ));
        }
        if raw.settle_type.is_some() {
            return Err(format!(
                "{ERR_PAYLOAD_TYPE}: type is set per settle by the resource server; \
                 a client payload must not carry it"
            ));
        }
        let nonce =
            raw.nonce.as_str().and_then(decimal_u64).ok_or_else(|| {
                format!("invalid payload: nonce {} is not a decimal u64", raw.nonce)
            })?;
        let open_slot = slot_from_value(&raw.open_slot)
            .ok_or_else(|| format!("invalid payload: openSlot {} is not a u64", raw.open_slot))?;
        Ok(Self {
            from: raw.from,
            max_amount: raw.max_amount,
            expires_at: raw.expires_at,
            valid_after: raw.valid_after,
            nonce: UptoNonce(nonce),
            channel_id: raw.channel_id,
            deposit: raw.deposit,
            authorized_signer: raw.authorized_signer,
            open_slot: Slot(open_slot),
            open_transaction: raw.open_transaction,
        })
    }
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
                token_program: None,
                fee_payer: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
                receiver_authorizer: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
                withdraw_delay: 900,
                recent_blockhash: None,
                last_valid_block_height: None,
                recent_slot: None,
                valid_after: None,
                memo: None,
                transaction_versions: None,
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
        assert_eq!(json["extra"]["feePayer"], req.extra.fee_payer);
        assert_eq!(
            json["extra"]["receiverAuthorizer"],
            req.extra.receiver_authorizer
        );
        assert_eq!(json["extra"]["withdrawDelay"], 900);
        assert!(json["extra"].get("assetTransferMethod").is_none());
        assert!(json["extra"].get("facilitatorAddress").is_none());
        assert!(json["extra"].get("facilitatorFee").is_none());
        assert!(json["extra"].get("channelProgram").is_none());

        let back: UptoRequirements = serde_json::from_value(json).unwrap();
        assert_eq!(back.max_amount().unwrap(), 1_000_000);
        assert_eq!(back.scheme, "upto");
        assert_eq!(back.extra.withdraw_delay, 900);
    }

    #[test]
    fn payload_omits_optional_fields_and_parses_amounts() {
        let payload = UptoPayload {
            from: "Payer1111111111111111111111111111111111111".to_string(),
            max_amount: "1000000".to_string(),
            expires_at: 4_102_444_800,
            valid_after: 0,
            nonce: UptoNonce::new(7),
            channel_id: "Chan1111111111111111111111111111111111111".to_string(),
            deposit: "1000000".to_string(),
            authorized_signer: "Op11111111111111111111111111111111111111111".to_string(),
            open_slot: Slot::new(55555),
            open_transaction: Some("base64tx".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"openTransaction\":\"base64tx\""));
        assert!(json.contains("\"openSlot\":\"55555\""));
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
                "nonce": "7",
                "channelId": "Chan1111111111111111111111111111111111111",
                "deposit": "1000000",
                "authorizedSigner": "Op11111111111111111111111111111111111111111",
                "openSlot": "55555",
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
        assert_eq!(env.payload.open_slot, Slot::new(55555));

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

    fn client_payload() -> serde_json::Value {
        serde_json::json!({
            "from": "Payer1111111111111111111111111111111111111",
            "maxAmount": "1000000",
            "expiresAt": 4_102_444_800i64,
            "validAfter": 0,
            "nonce": "4242",
            "channelId": "Chan1111111111111111111111111111111111111",
            "deposit": "1000000",
            "authorizedSigner": "Op11111111111111111111111111111111111111111",
            "openSlot": "55555",
            "openTransaction": "base64tx",
        })
    }

    fn parse(value: serde_json::Value) -> Result<UptoPayload, String> {
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    #[test]
    fn client_payload_parses() {
        let payload = parse(client_payload()).unwrap();
        assert_eq!(payload.nonce.get(), 4242);
        assert_eq!(payload.open_slot.get(), 55555);
    }

    #[test]
    fn client_payload_refuses_settle_only_fields() {
        // Phase 3 step 0: presence alone, an empty string or null included.
        for voucher in [
            serde_json::json!("sig"),
            serde_json::json!(""),
            serde_json::Value::Null,
        ] {
            let mut p = client_payload();
            p["voucherSignature"] = voucher;
            let err = parse(p).unwrap_err();
            assert!(err.contains(ERR_UNEXPECTED_VOUCHER), "{err}");
        }
        for kind in [serde_json::json!("deposit"), serde_json::json!("claim")] {
            let mut p = client_payload();
            p["type"] = kind;
            let err = parse(p).unwrap_err();
            assert!(err.contains(ERR_PAYLOAD_TYPE), "{err}");
        }
    }

    #[test]
    fn nonce_must_be_a_decimal_u64_string() {
        for bad in [
            serde_json::json!("abc"),
            serde_json::json!(""),
            serde_json::json!("+5"),
            serde_json::json!(" 5"),
            serde_json::json!("18446744073709551616"),
            serde_json::json!(5),
        ] {
            let mut p = client_payload();
            p["nonce"] = bad.clone();
            let err = parse(p).unwrap_err();
            assert!(
                err.contains("nonce") && err.contains("not a decimal u64"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn open_slot_reads_the_spec_number_and_the_decimal_string() {
        let mut p = client_payload();
        p["openSlot"] = serde_json::json!(55555);
        assert_eq!(parse(p).unwrap().open_slot.get(), 55555);
        for bad in [
            serde_json::json!("abc"),
            serde_json::json!("-1"),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::Value::Null,
        ] {
            let mut p = client_payload();
            p["openSlot"] = bad.clone();
            let err = parse(p).unwrap_err();
            assert!(
                err.contains("openSlot") && err.contains("not a u64"),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn recent_slot_reads_the_spec_number_and_the_decimal_string() {
        let mut req = serde_json::to_value(requirements()).unwrap();
        req["extra"]["recentSlot"] = serde_json::json!(341_000_000u64);
        let parsed: UptoRequirements = serde_json::from_value(req.clone()).unwrap();
        assert_eq!(parsed.extra.recent_slot, Some(Slot::new(341_000_000)));
        req["extra"]["recentSlot"] = serde_json::json!("341000000");
        let parsed: UptoRequirements = serde_json::from_value(req.clone()).unwrap();
        assert_eq!(parsed.extra.recent_slot, Some(Slot::new(341_000_000)));
        req["extra"]["recentSlot"] = serde_json::json!("soon");
        assert!(serde_json::from_value::<UptoRequirements>(req).is_err());
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
