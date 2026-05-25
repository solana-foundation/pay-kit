//! Core challenge, credential, and receipt types.

use serde::{Deserialize, Serialize};

use super::types::{Base64UrlJson, IntentName, MethodName, ReceiptStatus};

/// Payment challenge from server (parsed from WWW-Authenticate header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentChallenge {
    pub id: String,
    pub realm: String,
    pub method: MethodName,
    pub intent: IntentName,
    /// Method+intent specific request data (base64url-encoded JSON).
    pub request: Base64UrlJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<Base64UrlJson>,
}

impl PaymentChallenge {
    /// Create a new payment challenge with an explicit ID.
    pub fn new(
        id: impl Into<String>,
        realm: impl Into<String>,
        method: impl Into<MethodName>,
        intent: impl Into<IntentName>,
        request: Base64UrlJson,
    ) -> Self {
        Self {
            id: id.into(),
            realm: realm.into(),
            method: method.into(),
            intent: intent.into(),
            request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        }
    }

    /// Create a new payment challenge with an HMAC-bound ID.
    ///
    /// Enables stateless verification without storing challenge state.
    pub fn with_secret_key(
        secret_key: &str,
        realm: impl Into<String>,
        method: impl Into<MethodName>,
        intent: impl Into<IntentName>,
        request: Base64UrlJson,
    ) -> Self {
        let realm = realm.into();
        let method = method.into();
        let intent = intent.into();
        let id = compute_challenge_id(
            secret_key,
            &realm,
            method.as_str(),
            intent.as_str(),
            request.raw(),
            None,
            None,
            None,
        );
        Self {
            id,
            realm,
            method,
            intent,
            request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        }
    }

    /// Create with HMAC-bound ID including all optional fields.
    #[allow(clippy::too_many_arguments)]
    pub fn with_secret_key_full(
        secret_key: &str,
        realm: impl Into<String>,
        method: impl Into<MethodName>,
        intent: impl Into<IntentName>,
        request: Base64UrlJson,
        expires: Option<&str>,
        digest: Option<&str>,
        description: Option<&str>,
        opaque: Option<Base64UrlJson>,
    ) -> Self {
        let realm = realm.into();
        let method = method.into();
        let intent = intent.into();
        let id = compute_challenge_id(
            secret_key,
            &realm,
            method.as_str(),
            intent.as_str(),
            request.raw(),
            expires,
            digest,
            opaque.as_ref().map(|o| o.raw()),
        );
        Self {
            id,
            realm,
            method,
            intent,
            request,
            expires: expires.map(String::from),
            description: description.map(String::from),
            digest: digest.map(String::from),
            opaque,
        }
    }

    pub fn with_expires(mut self, expires: impl Into<String>) -> Self {
        self.expires = Some(expires.into());
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Create a challenge echo for use in credentials.
    pub fn to_echo(&self) -> ChallengeEcho {
        ChallengeEcho {
            id: self.id.clone(),
            realm: self.realm.clone(),
            method: self.method.clone(),
            intent: self.intent.clone(),
            request: self.request.clone(),
            expires: self.expires.clone(),
            digest: self.digest.clone(),
            opaque: self.opaque.clone(),
        }
    }

    /// Format as WWW-Authenticate header value.
    pub fn to_header(&self) -> Result<String, crate::error::Error> {
        super::format_www_authenticate(self)
    }

    /// Parse from a WWW-Authenticate header value.
    pub fn from_header(header: &str) -> Result<Self, crate::error::Error> {
        super::parse_www_authenticate(header)
    }

    /// Verify that this challenge's ID matches the expected HMAC.
    pub fn verify(&self, secret_key: &str) -> bool {
        let expected_id = compute_challenge_id(
            secret_key,
            &self.realm,
            self.method.as_str(),
            self.intent.as_str(),
            self.request.raw(),
            self.expires.as_deref(),
            self.digest.as_deref(),
            self.opaque.as_ref().map(|o| o.raw()),
        );
        constant_time_eq(&self.id, &expected_id)
    }

    /// Returns true if the challenge has expired.
    pub fn is_expired(&self) -> bool {
        match &self.expires {
            None => false,
            Some(s) => {
                match time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                {
                    Ok(expires) => expires <= time::OffsetDateTime::now_utc(),
                    Err(_) => true, // fail-closed
                }
            }
        }
    }
}

/// Compute an HMAC-SHA256 challenge ID from challenge parameters.
///
/// Concatenates `realm|method|intent|request|expires|digest|opaque` and
/// computes HMAC-SHA256 with the secret key, then base64url-encodes.
#[allow(clippy::too_many_arguments)]
pub fn compute_challenge_id(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let hmac_input = [
        realm,
        method,
        intent,
        request,
        expires.unwrap_or(""),
        digest.unwrap_or(""),
        opaque.unwrap_or(""),
    ]
    .join("|");

    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(hmac_input.as_bytes());
    let result = mac.finalize();

    super::base64url_encode(&result.into_bytes())
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Challenge echo in credential (echoes server challenge parameters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeEcho {
    pub id: String,
    pub realm: String,
    pub method: MethodName,
    pub intent: IntentName,
    pub request: Base64UrlJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<Base64UrlJson>,
}

/// Payment credential from client (sent in Authorization header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredential {
    pub challenge: ChallengeEcho,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Payment payload (method/intent-specific JSON).
    pub payload: serde_json::Value,
}

impl PaymentCredential {
    pub fn new(challenge: ChallengeEcho, payload: impl Serialize) -> Self {
        Self {
            challenge,
            source: None,
            payload: serde_json::to_value(payload).expect("payload must be serializable"),
        }
    }

    pub fn with_source(
        challenge: ChallengeEcho,
        source: impl Into<String>,
        payload: impl Serialize,
    ) -> Self {
        Self {
            challenge,
            source: Some(source.into()),
            payload: serde_json::to_value(payload).expect("payload must be serializable"),
        }
    }

    /// Parse from an Authorization header value.
    pub fn from_header(header: &str) -> Result<Self, crate::error::Error> {
        super::parse_authorization(header)
    }

    /// Deserialize the payload as a specific type.
    pub fn payload_as<T: serde::de::DeserializeOwned>(&self) -> Result<T, crate::error::Error> {
        serde_json::from_value(self.payload.clone())
            .map_err(|e| crate::error::Error::Other(format!("payload deserialization failed: {e}")))
    }

    /// Create a DID for a Solana address.
    ///
    /// Format: `did:pkh:solana:{chain_id}:{address}`
    pub fn solana_did(chain_id: &str, address: &str) -> String {
        format!("did:pkh:solana:{chain_id}:{address}")
    }
}

/// Payment receipt from server (parsed from Payment-Receipt header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub status: ReceiptStatus,
    pub method: MethodName,
    pub timestamp: String,
    pub reference: String,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
}

impl Receipt {
    /// Create a successful payment receipt.
    pub fn success(
        method: impl Into<MethodName>,
        reference: impl Into<String>,
        challenge_id: impl Into<String>,
    ) -> Self {
        Self {
            status: ReceiptStatus::Success,
            method: method.into(),
            timestamp: now_iso8601(),
            reference: reference.into(),
            challenge_id: challenge_id.into(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == ReceiptStatus::Success
    }

    /// Format as Payment-Receipt header value.
    pub fn to_header(&self) -> Result<String, crate::error::Error> {
        super::format_receipt(self)
    }
}

fn now_iso8601() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_hmac_verify() {
        let challenge = PaymentChallenge::with_secret_key(
            "test-secret",
            "api.example.com",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
        );
        assert!(challenge.verify("test-secret"));
        assert!(!challenge.verify("wrong-secret"));
    }

    #[test]
    fn challenge_echo_roundtrip() {
        let challenge = PaymentChallenge::new(
            "id-123",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
        );
        let echo = challenge.to_echo();
        assert_eq!(echo.id, "id-123");
        assert_eq!(echo.method.as_str(), "solana");
    }

    #[test]
    fn receipt_creation() {
        let receipt = Receipt::success("solana", "5UfDuX...", "challenge-1");
        assert!(receipt.is_success());
        assert_eq!(receipt.method.as_str(), "solana");
        assert_eq!(receipt.challenge_id, "challenge-1");
    }

    // ── with_secret_key_full coverage ──

    #[test]
    fn challenge_with_secret_key_full_verify() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "5000"})).unwrap();
        let opaque = Base64UrlJson::from_value(&serde_json::json!({"context": "xyz"})).unwrap();
        let challenge = PaymentChallenge::with_secret_key_full(
            "my-secret",
            "realm.example.com",
            "solana",
            "charge",
            request,
            Some("2099-01-01T00:00:00Z"),
            Some("sha-256=abc123"),
            Some("Pay for coffee"),
            Some(opaque),
        );
        assert!(challenge.verify("my-secret"));
        assert!(!challenge.verify("other-secret"));
        assert_eq!(challenge.expires.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert_eq!(challenge.digest.as_deref(), Some("sha-256=abc123"));
        assert_eq!(challenge.description.as_deref(), Some("Pay for coffee"));
        assert!(challenge.opaque.is_some());
    }

    #[test]
    fn challenge_with_secret_key_full_no_optionals() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "100"})).unwrap();
        let challenge = PaymentChallenge::with_secret_key_full(
            "secret", "realm", "solana", "charge", request, None, None, None, None,
        );
        assert!(challenge.verify("secret"));
        assert!(challenge.expires.is_none());
        assert!(challenge.digest.is_none());
        assert!(challenge.description.is_none());
        assert!(challenge.opaque.is_none());
    }

    // ── builder methods ──

    #[test]
    fn challenge_with_expires() {
        let challenge = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
        .with_expires("2099-12-31T23:59:59Z");
        assert_eq!(challenge.expires.as_deref(), Some("2099-12-31T23:59:59Z"));
    }

    #[test]
    fn challenge_with_description() {
        let challenge = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
        .with_description("A test payment");
        assert_eq!(challenge.description.as_deref(), Some("A test payment"));
    }

    // ── is_expired tests ──

    #[test]
    fn challenge_not_expired_when_no_expires() {
        let challenge = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        );
        assert!(!challenge.is_expired());
    }

    #[test]
    fn challenge_expired_in_the_past() {
        let challenge = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
        .with_expires("2020-01-01T00:00:00Z");
        assert!(challenge.is_expired());
    }

    #[test]
    fn challenge_not_expired_in_the_future() {
        let challenge = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
        .with_expires("2099-01-01T00:00:00Z");
        assert!(!challenge.is_expired());
    }

    #[test]
    fn challenge_expired_with_invalid_timestamp() {
        // Invalid timestamps should be treated as expired (fail-closed)
        let mut challenge = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        );
        challenge.expires = Some("not-a-date".to_string());
        assert!(challenge.is_expired());
    }

    // ── to_echo preserves all fields ──

    #[test]
    fn to_echo_preserves_optional_fields() {
        let opaque = Base64UrlJson::from_value(&serde_json::json!({"nonce": "abc"})).unwrap();
        let mut challenge = PaymentChallenge::new(
            "id-456",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"x": 1})).unwrap(),
        );
        challenge.expires = Some("2099-01-01T00:00:00Z".to_string());
        challenge.digest = Some("sha-256=deadbeef".to_string());
        challenge.opaque = Some(opaque);

        let echo = challenge.to_echo();
        assert_eq!(echo.id, "id-456");
        assert_eq!(echo.expires.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert_eq!(echo.digest.as_deref(), Some("sha-256=deadbeef"));
        assert!(echo.opaque.is_some());
    }

    // ── to_header / from_header roundtrip ──

    #[test]
    fn challenge_to_header_from_header_roundtrip() {
        let challenge = PaymentChallenge::new(
            "round-trip-id",
            "my-realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "999"})).unwrap(),
        );
        let header = challenge.to_header().unwrap();
        let parsed = PaymentChallenge::from_header(&header).unwrap();
        assert_eq!(parsed.id, "round-trip-id");
        assert_eq!(parsed.realm, "my-realm");
        assert_eq!(parsed.method.as_str(), "solana");
        assert_eq!(parsed.intent.as_str(), "charge");
    }

    // ── compute_challenge_id determinism ──

    #[test]
    fn compute_challenge_id_deterministic() {
        let id1 = compute_challenge_id("key", "realm", "solana", "charge", "req", None, None, None);
        let id2 = compute_challenge_id("key", "realm", "solana", "charge", "req", None, None, None);
        assert_eq!(id1, id2);
    }

    #[test]
    fn compute_challenge_id_changes_with_any_param() {
        let base =
            compute_challenge_id("key", "realm", "solana", "charge", "req", None, None, None);
        let diff_key =
            compute_challenge_id("key2", "realm", "solana", "charge", "req", None, None, None);
        let diff_realm =
            compute_challenge_id("key", "other", "solana", "charge", "req", None, None, None);
        let diff_method =
            compute_challenge_id("key", "realm", "bitcoin", "charge", "req", None, None, None);
        let diff_intent = compute_challenge_id(
            "key",
            "realm",
            "solana",
            "subscribe",
            "req",
            None,
            None,
            None,
        );
        let diff_request =
            compute_challenge_id("key", "realm", "solana", "charge", "xyz", None, None, None);
        let with_expires = compute_challenge_id(
            "key",
            "realm",
            "solana",
            "charge",
            "req",
            Some("2099-01-01T00:00:00Z"),
            None,
            None,
        );
        let with_digest = compute_challenge_id(
            "key",
            "realm",
            "solana",
            "charge",
            "req",
            None,
            Some("sha-256=abc"),
            None,
        );
        let with_opaque = compute_challenge_id(
            "key",
            "realm",
            "solana",
            "charge",
            "req",
            None,
            None,
            Some("opaque-data"),
        );

        assert_ne!(base, diff_key);
        assert_ne!(base, diff_realm);
        assert_ne!(base, diff_method);
        assert_ne!(base, diff_intent);
        assert_ne!(base, diff_request);
        assert_ne!(base, with_expires);
        assert_ne!(base, with_digest);
        assert_ne!(base, with_opaque);
    }

    // ── constant_time_eq ──

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq("hello", "hello"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn constant_time_eq_different_content() {
        assert!(!constant_time_eq("hello", "world"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq("short", "longer-string"));
    }

    // ── PaymentCredential tests ──

    #[test]
    fn credential_new_and_payload_as() {
        let echo = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
        .to_echo();
        let payload = serde_json::json!({"type": "transaction", "transaction": "base64data"});
        let credential = PaymentCredential::new(echo, payload.clone());
        assert!(credential.source.is_none());
        let decoded: serde_json::Value = credential.payload_as().unwrap();
        assert_eq!(decoded["type"], "transaction");
    }

    #[test]
    fn credential_with_source() {
        let echo = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
        .to_echo();
        let payload = serde_json::json!({"sig": "abc"});
        let credential =
            PaymentCredential::with_source(echo, "did:pkh:solana:mainnet:Abc123", payload);
        assert_eq!(
            credential.source.as_deref(),
            Some("did:pkh:solana:mainnet:Abc123")
        );
    }

    #[test]
    fn credential_payload_as_wrong_type() {
        let echo = PaymentChallenge::new(
            "id",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        )
        .to_echo();
        let credential = PaymentCredential::new(echo, serde_json::json!({"not": "a number"}));
        // Try to deserialize as u64 — should fail
        let result: Result<u64, _> = credential.payload_as();
        assert!(result.is_err());
    }

    #[test]
    fn solana_did_format() {
        let did = PaymentCredential::solana_did("mainnet", "Abc123XYZ");
        assert_eq!(did, "did:pkh:solana:mainnet:Abc123XYZ");
    }

    #[test]
    fn solana_did_devnet() {
        let did = PaymentCredential::solana_did("devnet", "MyAddress");
        assert_eq!(did, "did:pkh:solana:devnet:MyAddress");
    }

    // ── Receipt tests ──

    #[test]
    fn receipt_with_challenge_id() {
        let receipt = Receipt::success("solana", "sig123", "ch-456");
        assert!(receipt.is_success());
        assert_eq!(receipt.challenge_id, "ch-456");
        assert_eq!(receipt.reference, "sig123");
    }

    #[test]
    fn receipt_timestamp_is_valid_rfc3339() {
        let receipt = Receipt::success("solana", "ref", "ch-1");
        // Should parse as RFC3339
        let parsed = time::OffsetDateTime::parse(
            &receipt.timestamp,
            &time::format_description::well_known::Rfc3339,
        );
        assert!(parsed.is_ok());
    }

    #[test]
    fn receipt_to_header_roundtrip() {
        let receipt = Receipt::success("solana", "tx-sig-abc", "ch-roundtrip");
        let header = receipt.to_header().unwrap();
        let parsed = super::super::parse_receipt(&header).unwrap();
        assert_eq!(parsed.reference, "tx-sig-abc");
        assert!(parsed.is_success());
    }
}
