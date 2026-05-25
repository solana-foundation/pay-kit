//! Core type definitions for the Web Payment Auth protocol.
//!
//! Zero heavy dependencies — only serde, serde_json, base64.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::Deref;

use crate::error::Error;

/// Payment method identifier (newtype over String).
///
/// Per spec, method identifiers MUST be lowercase ASCII strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MethodName(String);

impl MethodName {
    /// Create a new method name, normalizing to lowercase per spec.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn eq_ignore_ascii_case(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
    }

    /// Check if the method name contains only valid ASCII lowercase characters.
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.chars().all(|c| c.is_ascii_lowercase())
    }
}

impl Deref for MethodName {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for MethodName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for MethodName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for MethodName {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// Payment intent identifier (newtype over String).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IntentName(String);

impl IntentName {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_charge(&self) -> bool {
        self.0.eq_ignore_ascii_case("charge")
    }
}

impl Deref for IntentName {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for IntentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for IntentName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for IntentName {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// A JSON value encoded as base64url.
///
/// Preserves the original encoding for credential echo (avoiding re-serialization issues).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Base64UrlJson {
    raw: String,
}

impl Base64UrlJson {
    /// Create from a raw base64url string (does not validate).
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }

    /// Create from a JSON Value using canonical JSON serialization.
    pub fn from_value(value: &serde_json::Value) -> Result<Self, Error> {
        let json = serde_json_canonicalizer::to_string(value)
            .map_err(|e| Error::Other(format!("Canonical JSON failed: {e}")))?;
        Ok(Self {
            raw: base64url_encode(json.as_bytes()),
        })
    }

    /// Create from a serializable type using canonical JSON.
    pub fn from_typed<T: Serialize>(value: &T) -> Result<Self, Error> {
        let json = serde_json_canonicalizer::to_string(value)
            .map_err(|e| Error::Other(format!("Canonical JSON failed: {e}")))?;
        Ok(Self {
            raw: base64url_encode(json.as_bytes()),
        })
    }

    /// Get the raw base64url string.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Decode to a JSON Value.
    pub fn decode_value(&self) -> Result<serde_json::Value, Error> {
        let bytes = base64url_decode(&self.raw)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Other(format!("Invalid JSON in base64url: {e}")))
    }

    /// Decode to a typed struct.
    pub fn decode<T: for<'de> Deserialize<'de>>(&self) -> Result<T, Error> {
        let bytes = base64url_decode(&self.raw)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| Error::Other(format!("Failed to decode base64url JSON: {e}")))
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

impl Serialize for Base64UrlJson {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64UrlJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::from_raw)
    }
}

/// Encode bytes as base64url (no padding).
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode a base64url string to bytes.
///
/// Accepts both URL-safe and standard alphabets, with or without padding.
pub fn base64url_decode(input: &str) -> Result<Vec<u8>, Error> {
    let normalized: String = input
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();

    URL_SAFE_NO_PAD
        .decode(&normalized)
        .map_err(|e| Error::Other(format!("Invalid base64url: {e}")))
}

/// Payment receipt status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    Success,
}

impl fmt::Display for ReceiptStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_name_normalizes_to_lowercase() {
        let m: MethodName = "SOLANA".into();
        assert_eq!(m.as_str(), "solana");
        assert!(m.eq_ignore_ascii_case("Solana"));
        assert!(m.is_valid());
    }

    #[test]
    fn intent_name_variants() {
        let charge: IntentName = "charge".into();
        assert!(charge.is_charge());
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        assert!(!encoded.contains('='));
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64url_decode_accepts_standard_with_padding() {
        let data = b"hello world";
        let standard = base64::engine::general_purpose::STANDARD.encode(data);
        let decoded = base64url_decode(&standard).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64url_json_roundtrip() {
        let value = serde_json::json!({"amount": "1000", "currency": "USDC"});
        let b64 = Base64UrlJson::from_value(&value).unwrap();
        let decoded = b64.decode_value().unwrap();
        assert_eq!(decoded["amount"], "1000");
    }

    // ── MethodName edge cases ──

    #[test]
    fn method_name_from_string() {
        let m = MethodName::from("Bitcoin".to_string());
        assert_eq!(m.as_str(), "bitcoin");
    }

    #[test]
    fn method_name_display() {
        let m = MethodName::new("solana");
        assert_eq!(format!("{m}"), "solana");
    }

    #[test]
    fn method_name_deref() {
        let m = MethodName::new("solana");
        // Deref to &str — can call str methods
        assert!(m.starts_with("sol"));
        assert_eq!(m.len(), 6);
    }

    #[test]
    fn method_name_is_valid_empty() {
        let m = MethodName::new("");
        assert!(!m.is_valid());
    }

    #[test]
    fn method_name_is_valid_with_numbers() {
        // Numbers are not lowercase ASCII letters
        let m = MethodName::new("sol123");
        assert!(!m.is_valid());
    }

    #[test]
    fn method_name_equality() {
        let a = MethodName::new("solana");
        let b = MethodName::new("SOLANA");
        assert_eq!(a, b); // Both normalize to lowercase
    }

    #[test]
    fn method_name_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(MethodName::new("solana"));
        assert!(set.contains(&MethodName::new("SOLANA")));
    }

    // ── IntentName edge cases ──

    #[test]
    fn intent_name_from_string() {
        let i = IntentName::from("Charge".to_string());
        assert_eq!(i.as_str(), "charge");
    }

    #[test]
    fn intent_name_display() {
        let i = IntentName::new("charge");
        assert_eq!(format!("{i}"), "charge");
    }

    #[test]
    fn intent_name_deref() {
        let i = IntentName::new("charge");
        assert!(i.starts_with("ch"));
    }

    #[test]
    fn intent_name_is_charge_case_insensitive() {
        let i = IntentName::new("CHARGE");
        assert!(i.is_charge()); // stored as "charge", eq_ignore_ascii_case
    }

    #[test]
    fn intent_name_is_not_charge() {
        let i = IntentName::new("subscribe");
        assert!(!i.is_charge());
    }

    // ── Base64UrlJson edge cases ──

    #[test]
    fn base64url_json_from_raw() {
        let b = Base64UrlJson::from_raw("eyJhIjoxfQ");
        assert_eq!(b.raw(), "eyJhIjoxfQ");
        assert!(!b.is_empty());
    }

    #[test]
    fn base64url_json_empty() {
        let b = Base64UrlJson::default();
        assert!(b.is_empty());
        assert_eq!(b.raw(), "");
    }

    #[test]
    fn base64url_json_from_typed() {
        #[derive(Serialize)]
        struct Req {
            amount: String,
        }
        let req = Req {
            amount: "500".to_string(),
        };
        let b = Base64UrlJson::from_typed(&req).unwrap();
        assert!(!b.is_empty());

        let decoded = b.decode_value().unwrap();
        assert_eq!(decoded["amount"], "500");
    }

    #[test]
    fn base64url_json_decode_typed() {
        #[derive(Deserialize, Debug, PartialEq)]
        struct Req {
            amount: String,
        }
        let b = Base64UrlJson::from_value(&serde_json::json!({"amount": "123"})).unwrap();
        let req: Req = b.decode().unwrap();
        assert_eq!(
            req,
            Req {
                amount: "123".to_string()
            }
        );
    }

    #[test]
    fn base64url_json_decode_invalid_base64() {
        let b = Base64UrlJson::from_raw("!!!invalid!!!");
        assert!(b.decode_value().is_err());
    }

    #[test]
    fn base64url_json_decode_valid_base64_invalid_json() {
        // base64url of "not json"
        let b = Base64UrlJson::from_raw(base64url_encode(b"not json"));
        assert!(b.decode_value().is_err());
    }

    #[test]
    fn base64url_json_serde_roundtrip() {
        let original = Base64UrlJson::from_value(&serde_json::json!({"key": "val"})).unwrap();
        let json_str = serde_json::to_string(&original).unwrap();
        let deserialized: Base64UrlJson = serde_json::from_str(&json_str).unwrap();
        assert_eq!(original, deserialized);
    }

    // ── base64url_decode edge cases ──

    #[test]
    fn base64url_decode_empty() {
        let decoded = base64url_decode("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn base64url_decode_strips_padding() {
        // "hello" in standard base64 with padding: "aGVsbG8="
        let decoded = base64url_decode("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn base64url_decode_converts_plus_and_slash() {
        // Standard base64 uses + and /, URL-safe uses - and _
        // Encode some data that would produce + or / in standard base64
        let data = vec![0xfb, 0xff, 0xfe]; // produces +/characters in standard
        let standard = base64::engine::general_purpose::STANDARD.encode(&data);
        let decoded = base64url_decode(&standard).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64url_decode_invalid_chars() {
        assert!(base64url_decode("@#$%^&").is_err());
    }

    // ── ReceiptStatus ──

    #[test]
    fn receipt_status_display() {
        assert_eq!(format!("{}", ReceiptStatus::Success), "success");
    }

    #[test]
    fn receipt_status_serde() {
        let json = serde_json::to_string(&ReceiptStatus::Success).unwrap();
        assert_eq!(json, "\"success\"");
        let deserialized: ReceiptStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ReceiptStatus::Success);
    }
}
