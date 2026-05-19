//! Subscription intent request type and supporting payloads.
//!
//! The subscription intent represents a recurring fixed-amount payment
//! authorized once per billing period through an on-chain delegation.
//! Activation atomically creates the delegation and executes the first
//! billing-period charge; renewals are server-driven on-chain transactions
//! and do not produce HTTP credentials.

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Billing period unit. The Solana profile supports `day` and `week` only;
/// `month` is rejected because the on-chain program uses fixed elapsed
/// seconds and cannot represent calendar-month cadence exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionPeriodUnit {
    #[default]
    Day,
    Week,
}

impl SubscriptionPeriodUnit {
    /// Map a `(unit, count)` pair to the subscriptions program's
    /// `period_hours` value.
    ///
    /// Returns an error if the count is out of range for the unit or if the
    /// resulting `period_hours` exceeds the program's `[1, 8760]` bound.
    pub fn to_period_hours(self, period_count: u64) -> Result<u64, Error> {
        if period_count == 0 {
            return Err(Error::Other(
                "periodCount must be a positive integer".into(),
            ));
        }
        match self {
            SubscriptionPeriodUnit::Day => {
                if period_count > 365 {
                    return Err(Error::Other(format!(
                        "periodCount={period_count} for periodUnit=\"day\" exceeds 365"
                    )));
                }
                Ok(period_count * 24)
            }
            SubscriptionPeriodUnit::Week => {
                if period_count > 52 {
                    return Err(Error::Other(format!(
                        "periodCount={period_count} for periodUnit=\"week\" exceeds 52"
                    )));
                }
                Ok(period_count * 168)
            }
        }
    }
}

/// Subscription request (for the `subscription` intent on Solana).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionRequest {
    /// Per-period token amount in base units.
    pub amount: String,

    /// Base58 SPL token mint address (canonical wire form). Implementations
    /// MUST treat this consistently with `methodDetails.mint`.
    pub currency: String,

    /// Billing period unit. The Solana profile supports `day` and `week`
    /// only; `month` is rejected at the schema layer.
    pub period_unit: SubscriptionPeriodUnit,

    /// Decimal string count of `period_unit` values per billing period.
    pub period_count: String,

    /// Primary recipient wallet pubkey (base58).
    pub recipient: String,

    /// Optional RFC3339 expiry of the recurring authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_expires: Option<String>,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Merchant reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Solana-specific extension fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl SubscriptionRequest {
    /// Parse `period_count` as a `u64`.
    pub fn parse_period_count(&self) -> Result<u64, Error> {
        self.period_count
            .parse()
            .map_err(|_| Error::Other(format!("Invalid periodCount: {}", self.period_count)))
    }

    /// Parse `amount` as a `u64`.
    pub fn parse_amount(&self) -> Result<u64, Error> {
        self.amount
            .parse()
            .map_err(|_| Error::Other(format!("Invalid amount: {}", self.amount)))
    }

    /// Compute the on-chain `period_hours` for this request, validating both
    /// the period mapping and the program-level bound `[1, 8760]`.
    pub fn period_hours(&self) -> Result<u64, Error> {
        let count = self.parse_period_count()?;
        let hours = self.period_unit.to_period_hours(count)?;
        if hours == 0 || hours > 8760 {
            return Err(Error::Other(format!(
                "period_hours {hours} out of [1, 8760] range"
            )));
        }
        Ok(hours)
    }
}

/// Single-action credential payload. The Solana subscription profile only
/// defines `activate`; renewals are server-driven and cancellations are
/// out-of-band on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum SubscriptionAction {
    /// Activation: subscribe + first-period charge in one transaction.
    Activate(ActivatePayload),
}

/// Activation payload. Mirrors the Solana charge profile's two-mode shape:
/// `type="transaction"` (server broadcasts) or `type="signature"`
/// (client already broadcast).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActivatePayload {
    /// Payload type discriminator: `"transaction"` or `"signature"`.
    #[serde(rename = "type")]
    pub payload_type: String,

    /// Standard base64 of the serialized activation transaction
    /// (when `type="transaction"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,

    /// Base58 of the on-chain transaction signature (when `type="signature"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Extension fields placed on the standard Receipt's metadata for a
/// subscription activation or renewal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionReceiptExtensions {
    /// base64url (no padding) of the on-chain SubscriptionDelegation PDA.
    pub subscription_id: String,
    /// base58 of the on-chain Plan PDA.
    pub plan_id: String,
    /// Decimal index of the billing period (0 for activation).
    pub period_index: String,
    /// RFC3339 timestamp of the current period's start.
    pub period_start_ts: String,
    /// RFC3339 timestamp of the current period's end (exclusive).
    pub period_end_ts: String,
    /// RFC3339 effective subscription expiry, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_period_maps_to_hours() {
        assert_eq!(SubscriptionPeriodUnit::Day.to_period_hours(1).unwrap(), 24);
        assert_eq!(
            SubscriptionPeriodUnit::Day.to_period_hours(30).unwrap(),
            720
        );
        assert_eq!(
            SubscriptionPeriodUnit::Day.to_period_hours(365).unwrap(),
            8760
        );
    }

    #[test]
    fn week_period_maps_to_hours() {
        assert_eq!(
            SubscriptionPeriodUnit::Week.to_period_hours(1).unwrap(),
            168
        );
        assert_eq!(
            SubscriptionPeriodUnit::Week.to_period_hours(52).unwrap(),
            8736
        );
    }

    #[test]
    fn period_count_out_of_range_errors() {
        assert!(SubscriptionPeriodUnit::Day.to_period_hours(366).is_err());
        assert!(SubscriptionPeriodUnit::Week.to_period_hours(53).is_err());
        assert!(SubscriptionPeriodUnit::Day.to_period_hours(0).is_err());
    }

    #[test]
    fn request_serializes_camel_case() {
        let req = SubscriptionRequest {
            amount: "10000000".into(),
            currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(),
            recipient: "9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ".into(),
            subscription_expires: Some("2026-07-14T12:00:00Z".into()),
            external_id: Some("order-42".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"periodUnit\":\"day\""));
        assert!(json.contains("\"periodCount\":\"30\""));
        assert!(json.contains("\"subscriptionExpires\":\"2026-07-14T12:00:00Z\""));
        assert!(json.contains("\"externalId\":\"order-42\""));
    }

    #[test]
    fn rejects_unknown_period_unit_via_deserialization() {
        let json = r#"{"amount":"1","currency":"X","periodUnit":"month","periodCount":"1","recipient":"R"}"#;
        let parsed: Result<SubscriptionRequest, _> = serde_json::from_str(json);
        assert!(
            parsed.is_err(),
            "month must be rejected at the schema layer"
        );
    }

    #[test]
    fn period_hours_validates_range() {
        let req = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "30".into(),
            ..Default::default()
        };
        assert_eq!(req.period_hours().unwrap(), 720);

        let too_big = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "400".into(),
            ..Default::default()
        };
        assert!(too_big.period_hours().is_err());
    }

    #[test]
    fn activate_payload_pull_mode_roundtrip() {
        let action = SubscriptionAction::Activate(ActivatePayload {
            payload_type: "transaction".into(),
            transaction: Some("AQAAAA==".into()),
            signature: None,
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"action\":\"activate\""));
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(!json.contains("\"signature\""));
        let _back: SubscriptionAction = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn activate_payload_push_mode_roundtrip() {
        let action = SubscriptionAction::Activate(ActivatePayload {
            payload_type: "signature".into(),
            transaction: None,
            signature: Some("5J8KKKKK".into()),
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"type\":\"signature\""));
        assert!(json.contains("\"signature\":\"5J8KKKKK\""));
        let _back: SubscriptionAction = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn parse_amount_and_period_count() {
        let req = SubscriptionRequest {
            amount: "10000000".into(),
            period_count: "30".into(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 10_000_000);
        assert_eq!(req.parse_period_count().unwrap(), 30);

        let bad_amount = SubscriptionRequest {
            amount: "not-a-number".into(),
            period_count: "30".into(),
            ..Default::default()
        };
        assert!(bad_amount.parse_amount().is_err());

        let bad_count = SubscriptionRequest {
            amount: "1".into(),
            period_count: "abc".into(),
            ..Default::default()
        };
        assert!(bad_count.parse_period_count().is_err());
    }

    #[test]
    fn period_hours_bound_check() {
        // day*365 = 8760 — at the upper bound, accepted.
        let at_bound = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "365".into(),
            ..Default::default()
        };
        assert_eq!(at_bound.period_hours().unwrap(), 8760);

        // Bad period_count surfaces through period_hours().
        let bad = SubscriptionRequest {
            period_unit: SubscriptionPeriodUnit::Day,
            period_count: "not-a-number".into(),
            ..Default::default()
        };
        assert!(bad.period_hours().is_err());
    }

    #[test]
    fn activate_payload_default() {
        let p = ActivatePayload::default();
        assert!(p.transaction.is_none());
        assert!(p.signature.is_none());
        assert_eq!(p.payload_type, "");
    }

    #[test]
    fn period_unit_default_is_day() {
        let unit = SubscriptionPeriodUnit::default();
        assert_eq!(unit, SubscriptionPeriodUnit::Day);
    }

    #[test]
    fn receipt_extensions_default() {
        let ext = SubscriptionReceiptExtensions::default();
        assert_eq!(ext.subscription_id, "");
        assert_eq!(ext.plan_id, "");
        assert!(ext.expires_at.is_none());
    }

    #[test]
    fn receipt_extensions_serialize() {
        let ext = SubscriptionReceiptExtensions {
            subscription_id: "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE".into(),
            plan_id: "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT".into(),
            period_index: "0".into(),
            period_start_ts: "2026-01-15T12:03:10Z".into(),
            period_end_ts: "2026-02-14T12:03:10Z".into(),
            expires_at: Some("2026-07-14T12:00:00Z".into()),
        };
        let json = serde_json::to_string(&ext).unwrap();
        assert!(json.contains("\"subscriptionId\""));
        assert!(json.contains("\"planId\""));
        assert!(json.contains("\"periodIndex\":\"0\""));
        assert!(json.contains("\"periodStartTs\""));
        assert!(json.contains("\"periodEndTs\""));
        assert!(json.contains("\"expiresAt\""));
    }
}
