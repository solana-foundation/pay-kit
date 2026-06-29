//! `authenticate` intent — identity proof for HTTP requests bound to a
//! previously-established payment commitment (subscription, session) or
//! a server-defined free tier.
//!
//! The intent does not move funds. It carries a {{SIWS}}-style message
//! the client signs with its wallet; subsequent requests within the
//! server-defined validity window reuse the same signed payload as a
//! bearer credential.
//!
//! See `mpp-specs/specs/methods/solana/draft-solana-authenticate-00.md`
//! for the normative spec.

use serde::{Deserialize, Serialize};

/// Signature type used by the Solana profile.
pub const SIGNATURE_TYPE_ED25519: &str = "ed25519";
/// MPP-native signature scheme name. Distinct from `siws` (Phantom's
/// "Sign-In With Solana" used by x402) so MPP authenticate credentials
/// can't be replayed against an SIWS-only server expecting a different
/// canonical message body.
pub const SIGNATURE_SCHEME_SIWMPP: &str = "siwmpp";
/// Canonical message version this profile emits + accepts.
pub const SIWMPP_VERSION: &str = "1";

/// Resource-binding scheme: an active Solana SubscriptionDelegation PDA.
pub const RESOURCE_SCHEME_SOLANA_SUBSCRIPTION: &str = "solana-subscription";
/// Resource-binding scheme: an open Solana session id.
pub const RESOURCE_SCHEME_SOLANA_SESSION: &str = "solana-session";
/// Resource-binding scheme: an absolute HTTP URL gated by this token.
pub const RESOURCE_SCHEME_HTTP: &str = "http";

/// Method-specific challenge fields placed on `request.methodDetails`.
///
/// The Solana profile of the `authenticate` intent identifies the
/// chain via MPP's `network` slug (`mainnet`, `devnet`, `testnet`,
/// `localnet`) — the same identifier `charge` and `subscription` use
/// — rather than CAIP-2. Keeps the wire shape MPP-native and avoids
/// importing x402-side transport vocabulary.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateMethodDetails {
    /// MPP network slug the credential is bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// MUST be `"ed25519"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_type: Option<String>,
    /// MUST be `"siwmpp"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
}

impl AuthenticateMethodDetails {
    /// Method details for a Solana `authenticate` challenge on the
    /// given network slug.
    pub fn for_network(network: &str) -> Self {
        Self {
            network: Some(network.to_string()),
            signature_type: Some(SIGNATURE_TYPE_ED25519.to_string()),
            signature_scheme: Some(SIGNATURE_SCHEME_SIWMPP.to_string()),
        }
    }
}

/// Server-issued `authenticate` challenge payload (the request body
/// embedded in the `WWW-Authenticate` 402 header).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateRequest {
    /// Expected HTTP host for the protected resource.
    pub domain: String,
    /// Canonical origin URI of the protected resource.
    pub uri: String,
    /// SIWS message version. MUST be `"1"`.
    pub version: String,
    /// Server-generated nonce. Servers SHOULD derive this deterministically
    /// from server-side state so changing the state invalidates outstanding
    /// tokens.
    pub nonce: String,
    /// RFC3339 issuance time.
    pub issued_at: String,
    /// RFC3339 expiration time. The server MUST reject credentials whose
    /// matching challenge has expired.
    pub expiration_time: String,
    /// Optional RFC3339 not-before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional human-readable statement included verbatim in the signed
    /// message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// Optional server-assigned correlator echoed in the signed payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Resource bindings the token unlocks. Each entry is a URI of the form
    /// `<scheme>:<value>` — see the resource-scheme constants on this
    /// module for the registered schemes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    /// Method-specific extension fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_details: Option<AuthenticateMethodDetails>,
}

/// Signed credential carried in the retry's `Authorization: Payment …`
/// header.
///
/// The signed-message construction is identical to the SIWS canonical
/// form (see `format_canonical_message`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatePayload {
    /// Echoed from the challenge.
    pub domain: String,
    /// Echoed from the challenge.
    pub uri: String,
    /// Base58 signer pubkey.
    pub address: String,
    /// Echoed from the challenge.
    pub version: String,
    /// MPP network slug the signer chose. MUST equal the value the
    /// server advertised in `methodDetails.network`.
    pub network: String,
    /// Echoed from the challenge.
    pub nonce: String,
    /// Echoed from the challenge.
    pub issued_at: String,
    /// Echoed from the challenge.
    pub expiration_time: String,
    /// Echoed from the challenge when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Echoed from the challenge when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// Echoed from the challenge when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Echoed from the challenge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    /// Signature type. MUST be `"ed25519"`.
    #[serde(rename = "type")]
    pub signature_type: String,
    /// Optional signature scheme (`"siws"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    /// Base58 ed25519 signature over the canonical SIWS message.
    pub signature: String,
}

/// Render the SIWMPP canonical message bytes from a payload.
///
/// SIWMPP = Sign-In With MPP. The message layout is similar in spirit
/// to SIWS but uses MPP's `Network` slug instead of CAIP-2 `Chain ID`,
/// and an MPP-specific header so an SIWMPP credential can never be
/// replayed against an SIWS-only verifier.
///
/// ```text
/// <domain> wants you to authenticate with MPP:
/// <address>
///
/// <statement>
///
/// URI: <uri>
/// Version: <version>
/// Network: <network>
/// Nonce: <nonce>
/// Issued At: <issued_at>
/// Expiration Time: <expiration_time>
/// Not Before: <not_before>
/// Request ID: <request_id>
/// Resources:
/// - <resource[0]>
/// - <resource[1]>
/// ```
///
/// The statement block + leading blank line are omitted when `statement`
/// is unset. `Not Before`, `Request ID`, and the `Resources:` block are
/// each emitted only when present.
pub fn format_canonical_message(p: &AuthenticatePayload) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{} wants you to authenticate with MPP:\n{}",
        p.domain, p.address
    ));
    out.push('\n');

    if let Some(statement) = p.statement.as_deref().filter(|s| !s.is_empty()) {
        out.push('\n');
        out.push_str(statement);
        out.push('\n');
    }
    out.push('\n');

    out.push_str(&format!("URI: {}\n", p.uri));
    out.push_str(&format!("Version: {}\n", p.version));
    out.push_str(&format!("Network: {}\n", p.network));
    out.push_str(&format!("Nonce: {}\n", p.nonce));
    out.push_str(&format!("Issued At: {}", p.issued_at));

    if !p.expiration_time.is_empty() {
        out.push('\n');
        out.push_str(&format!("Expiration Time: {}", p.expiration_time));
    }
    if let Some(not_before) = p.not_before.as_deref().filter(|s| !s.is_empty()) {
        out.push('\n');
        out.push_str(&format!("Not Before: {not_before}"));
    }
    if let Some(request_id) = p.request_id.as_deref().filter(|s| !s.is_empty()) {
        out.push('\n');
        out.push_str(&format!("Request ID: {request_id}"));
    }
    if !p.resources.is_empty() {
        out.push('\n');
        out.push_str("Resources:");
        for r in &p.resources {
            out.push('\n');
            out.push_str(&format!("- {r}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> AuthenticatePayload {
        AuthenticatePayload {
            domain: "api.example.com".into(),
            uri: "https://api.example.com/v1".into(),
            address: "Hq5C2irSZkxxU6ifBzb4Er4pTMNqMB1ya9K8jmESeh2H".into(),
            version: SIWMPP_VERSION.into(),
            network: "mainnet".into(),
            nonce: "8s7d6f9a".into(),
            issued_at: "2026-05-29T22:25:22Z".into(),
            expiration_time: "2026-06-28T22:25:22Z".into(),
            not_before: None,
            statement: None,
            request_id: None,
            resources: vec![
                "solana-subscription:Hq5C2irSZkxxU6ifBzb4Er4pTMNqMB1ya9K8jmESeh2H".into(),
            ],
            signature_type: SIGNATURE_TYPE_ED25519.into(),
            signature_scheme: Some(SIGNATURE_SCHEME_SIWMPP.into()),
            signature: "".into(),
        }
    }

    #[test]
    fn canonical_message_renders_minimum_shape() {
        let msg = format_canonical_message(&sample_payload());
        // Header lines — MPP-native, not SIWS.
        assert!(msg.starts_with("api.example.com wants you to authenticate with MPP:\nHq5C2irSZk"));
        // Network slug, not CAIP-2 chain id.
        assert!(msg.contains("Network: mainnet"));
        // Statement omitted when None — there must be exactly one blank line
        // between the address line and the URI block.
        assert!(msg.contains(
            "Hq5C2irSZkxxU6ifBzb4Er4pTMNqMB1ya9K8jmESeh2H\n\nURI: https://api.example.com/v1"
        ));
        // Resources block present.
        assert!(msg.ends_with(
            "Resources:\n- solana-subscription:Hq5C2irSZkxxU6ifBzb4Er4pTMNqMB1ya9K8jmESeh2H"
        ));
    }

    #[test]
    fn canonical_message_inlines_statement_when_present() {
        let mut p = sample_payload();
        p.statement = Some("Sign in to use your active subscription.".into());
        let msg = format_canonical_message(&p);
        // Statement appears between address line and URI block, flanked by
        // blank lines.
        assert!(msg.contains(
            "Hq5C2irSZkxxU6ifBzb4Er4pTMNqMB1ya9K8jmESeh2H\n\n\
             Sign in to use your active subscription.\n\nURI:"
        ));
    }

    #[test]
    fn canonical_message_omits_optional_lines_when_unset() {
        let p = sample_payload();
        let msg = format_canonical_message(&p);
        assert!(!msg.contains("Not Before:"));
        assert!(!msg.contains("Request ID:"));
    }

    #[test]
    fn canonical_message_includes_optional_lines_when_set() {
        let mut p = sample_payload();
        p.not_before = Some("2026-05-29T22:00:00Z".into());
        p.request_id = Some("req-42".into());
        let msg = format_canonical_message(&p);
        assert!(msg.contains("Not Before: 2026-05-29T22:00:00Z"));
        assert!(msg.contains("Request ID: req-42"));
    }

    #[test]
    fn canonical_message_omits_resources_block_when_empty() {
        let mut p = sample_payload();
        p.resources.clear();
        let msg = format_canonical_message(&p);
        assert!(!msg.contains("Resources:"));
    }

    #[test]
    fn authenticate_request_round_trips_through_json() {
        let req = AuthenticateRequest {
            domain: "api.example.com".into(),
            uri: "https://api.example.com/v1".into(),
            version: SIWMPP_VERSION.into(),
            nonce: "abc".into(),
            issued_at: "2026-05-29T22:25:22Z".into(),
            expiration_time: "2026-06-28T22:25:22Z".into(),
            resources: vec!["solana-subscription:Hq5C2".into()],
            method_details: Some(AuthenticateMethodDetails::for_network("mainnet")),
            ..Default::default()
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: AuthenticateRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, req);
    }

    #[test]
    fn method_details_for_network_carries_expected_fields() {
        let md = AuthenticateMethodDetails::for_network("mainnet");
        assert_eq!(md.network.as_deref(), Some("mainnet"));
        assert_eq!(md.signature_type.as_deref(), Some(SIGNATURE_TYPE_ED25519));
        assert_eq!(
            md.signature_scheme.as_deref(),
            Some(SIGNATURE_SCHEME_SIWMPP)
        );
    }
}
