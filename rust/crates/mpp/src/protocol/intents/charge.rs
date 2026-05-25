//! Charge intent request type.
//!
//! The charge intent represents a one-time payment request. All fields are
//! strings to remain method-agnostic.

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Charge request (for charge intent).
///
/// All fields are strings to remain method-agnostic. Use the methods layer
/// for typed accessors (e.g., Solana-specific `SolanaMethodDetails`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChargeRequest {
    /// Amount in base units (e.g., lamports, micro-USDC).
    pub amount: String,

    /// Currency/asset identifier (e.g., "sol", mint address, "USDC").
    pub currency: String,

    /// Token decimals for amount conversion.
    #[serde(skip)]
    pub decimals: Option<u8>,

    /// Recipient address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Merchant reference ID.
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Method-specific extension fields.
    #[serde(rename = "methodDetails", skip_serializing_if = "Option::is_none")]
    pub method_details: Option<serde_json::Value>,
}

impl ChargeRequest {
    /// Apply the decimals transform, converting human-readable amount to base units.
    pub fn with_base_units(mut self) -> Result<Self, Error> {
        if let Some(decimals) = self.decimals {
            self.amount = super::parse_units(&self.amount, decimals)?;
            self.decimals = None;
        }
        Ok(self)
    }

    /// Parse the amount as u64.
    pub fn parse_amount(&self) -> Result<u64, Error> {
        self.amount
            .parse()
            .map_err(|_| Error::Other(format!("Invalid amount: {}", self.amount)))
    }

    /// Validate that the charge amount does not exceed a maximum.
    pub fn validate_max_amount(&self, max_amount: &str) -> Result<(), Error> {
        let amount = self.parse_amount()?;
        let max: u64 = max_amount
            .parse()
            .map_err(|_| Error::Other(format!("Invalid max amount: {max_amount}")))?;
        if amount > max {
            return Err(Error::Other(format!(
                "Amount {amount} exceeds maximum {max}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charge_request_serialization() {
        let req = ChargeRequest {
            amount: "10000".to_string(),
            currency: "USDC".to_string(),
            recipient: Some("CXhrFZ...".to_string()),
            method_details: Some(serde_json::json!({
                "network": "devnet",
                "decimals": 6
            })),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"amount\":\"10000\""));
        assert!(json.contains("\"methodDetails\""));
    }

    #[test]
    fn parse_amount() {
        let req = ChargeRequest {
            amount: "1000000".to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 1_000_000u64);
    }

    #[test]
    fn with_base_units() {
        let req = ChargeRequest {
            amount: "1.5".to_string(),
            decimals: Some(6),
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "1500000");
    }

    // ── parse_amount edge cases ──

    #[test]
    fn parse_amount_zero() {
        let req = ChargeRequest {
            amount: "0".to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), 0u64);
    }

    #[test]
    fn parse_amount_invalid() {
        let req = ChargeRequest {
            amount: "not_a_number".to_string(),
            ..Default::default()
        };
        assert!(req.parse_amount().is_err());
    }

    #[test]
    fn parse_amount_negative() {
        let req = ChargeRequest {
            amount: "-100".to_string(),
            ..Default::default()
        };
        assert!(req.parse_amount().is_err());
    }

    #[test]
    fn parse_amount_max_u64() {
        let req = ChargeRequest {
            amount: u64::MAX.to_string(),
            ..Default::default()
        };
        assert_eq!(req.parse_amount().unwrap(), u64::MAX);
    }

    // ── with_base_units edge cases ──

    #[test]
    fn with_base_units_no_decimals_is_noop() {
        let req = ChargeRequest {
            amount: "500".to_string(),
            decimals: None,
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "500");
    }

    #[test]
    fn with_base_units_zero_decimals() {
        let req = ChargeRequest {
            amount: "42".to_string(),
            decimals: Some(0),
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "42");
    }

    #[test]
    fn with_base_units_clears_decimals() {
        let req = ChargeRequest {
            amount: "1.0".to_string(),
            decimals: Some(6),
            ..Default::default()
        };
        let converted = req.with_base_units().unwrap();
        assert_eq!(converted.amount, "1000000");
        assert!(converted.decimals.is_none());
    }

    // ── validate_max_amount tests ──

    #[test]
    fn validate_max_amount_within_limit() {
        let req = ChargeRequest {
            amount: "500".to_string(),
            ..Default::default()
        };
        assert!(req.validate_max_amount("1000").is_ok());
    }

    #[test]
    fn validate_max_amount_at_limit() {
        let req = ChargeRequest {
            amount: "1000".to_string(),
            ..Default::default()
        };
        assert!(req.validate_max_amount("1000").is_ok());
    }

    #[test]
    fn validate_max_amount_exceeds() {
        let req = ChargeRequest {
            amount: "1001".to_string(),
            ..Default::default()
        };
        let err = req.validate_max_amount("1000");
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("exceeds maximum"));
    }

    #[test]
    fn validate_max_amount_invalid_amount() {
        let req = ChargeRequest {
            amount: "abc".to_string(),
            ..Default::default()
        };
        assert!(req.validate_max_amount("1000").is_err());
    }

    #[test]
    fn validate_max_amount_invalid_max() {
        let req = ChargeRequest {
            amount: "100".to_string(),
            ..Default::default()
        };
        assert!(req.validate_max_amount("not_a_number").is_err());
    }

    // ── serialization edge cases ──

    #[test]
    fn charge_request_deserialization() {
        let json =
            r#"{"amount":"5000","currency":"SOL","recipient":"Abc123","externalId":"ext-1"}"#;
        let req: ChargeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.amount, "5000");
        assert_eq!(req.currency, "SOL");
        assert_eq!(req.recipient.as_deref(), Some("Abc123"));
        assert_eq!(req.external_id.as_deref(), Some("ext-1"));
    }

    #[test]
    fn charge_request_omits_none_fields() {
        let req = ChargeRequest {
            amount: "100".to_string(),
            currency: "SOL".to_string(),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("recipient"));
        assert!(!json.contains("description"));
        assert!(!json.contains("externalId"));
        assert!(!json.contains("methodDetails"));
    }

    #[test]
    fn charge_request_decimals_not_serialized() {
        // decimals is #[serde(skip)] so should not appear in JSON
        let req = ChargeRequest {
            amount: "100".to_string(),
            currency: "SOL".to_string(),
            decimals: Some(9),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("decimals"));
    }

    #[test]
    fn charge_request_default() {
        let req = ChargeRequest::default();
        assert_eq!(req.amount, "");
        assert_eq!(req.currency, "");
        assert!(req.decimals.is_none());
        assert!(req.recipient.is_none());
    }
}
