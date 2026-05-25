//! Header parsing and formatting for Web Payment Auth.
//!
//! No regex — minimal dependencies.

use super::challenge::{PaymentChallenge, PaymentCredential, Receipt};
use super::types::{base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName};
use crate::error::Error;
use std::collections::HashMap;

const MAX_TOKEN_LEN: usize = 16 * 1024;

/// Header name for payment challenges (from server).
pub const WWW_AUTHENTICATE_HEADER: &str = "www-authenticate";

/// Header name for payment credentials (from client).
pub const AUTHORIZATION_HEADER: &str = "authorization";

/// Header name for payment receipts (from server).
pub const PAYMENT_RECEIPT_HEADER: &str = "payment-receipt";

/// Scheme identifier for the Payment authentication scheme.
pub const PAYMENT_SCHEME: &str = "Payment";

/// Parse a single WWW-Authenticate header into a PaymentChallenge.
pub fn parse_www_authenticate(header: &str) -> Result<PaymentChallenge, Error> {
    let rest = strip_payment_scheme(header)
        .ok_or_else(|| Error::Other("Expected 'Payment' scheme".into()))?;

    let params_str = rest
        .strip_prefix(' ')
        .or_else(|| rest.strip_prefix('\t'))
        .ok_or_else(|| Error::Other("Expected space after 'Payment' scheme".into()))?
        .trim_start();
    let params = parse_auth_params(params_str)?;

    let id = require_param(&params, "id")?.clone();
    if id.is_empty() {
        return Err(Error::Other("Empty 'id' parameter".into()));
    }
    let realm = require_param(&params, "realm")?.clone();
    let method_raw = require_param(&params, "method")?.clone();
    if method_raw.is_empty() || !method_raw.chars().all(|c| c.is_ascii_lowercase()) {
        return Err(Error::Other(format!(
            "Invalid method: \"{method_raw}\". Must be lowercase ASCII."
        )));
    }
    let method = MethodName::new(method_raw);
    let intent = IntentName::new(require_param(&params, "intent")?);
    let request_b64 = require_param(&params, "request")?.clone();

    let request_bytes = base64url_decode(&request_b64)?;
    let _ = serde_json::from_slice::<serde_json::Value>(&request_bytes)
        .map_err(|e| Error::Other(format!("Invalid JSON in request field: {e}")))?;
    let request = Base64UrlJson::from_raw(request_b64);

    Ok(PaymentChallenge {
        id,
        realm,
        method,
        intent,
        request,
        expires: params.get("expires").cloned(),
        description: params.get("description").cloned(),
        digest: params.get("digest").cloned(),
        opaque: params.get("opaque").map(Base64UrlJson::from_raw),
    })
}

/// Parse all Payment challenges from multiple WWW-Authenticate header values.
pub fn parse_www_authenticate_all<'a>(
    headers: impl IntoIterator<Item = &'a str>,
) -> Vec<Result<PaymentChallenge, Error>> {
    headers
        .into_iter()
        .flat_map(split_payment_challenge_values)
        .map(parse_www_authenticate)
        .collect()
}

fn split_payment_challenge_values(header: &str) -> Vec<&str> {
    let bytes = header.as_bytes();
    let mut starts = Vec::new();
    let mut in_quote = false;
    let mut escaped = false;
    let mut i = 0;

    while i < bytes.len() {
        let byte = bytes[i];
        if in_quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }

        if byte == b'"' {
            in_quote = true;
            i += 1;
            continue;
        }

        if is_payment_scheme_start(bytes, i) {
            starts.push(i);
            i += PAYMENT_SCHEME.len();
            continue;
        }

        i += 1;
    }

    starts
        .iter()
        .enumerate()
        .map(|(index, start)| {
            let end = starts.get(index + 1).copied().unwrap_or(header.len());
            header[*start..end].trim().trim_end_matches(',').trim()
        })
        .filter(|chunk| !chunk.is_empty())
        .collect()
}

fn is_payment_scheme_start(bytes: &[u8], index: usize) -> bool {
    let end = index.saturating_add(PAYMENT_SCHEME.len());
    if end >= bytes.len() {
        return false;
    }
    if !bytes[index..end].eq_ignore_ascii_case(PAYMENT_SCHEME.as_bytes()) {
        return false;
    }
    if !bytes[end].is_ascii_whitespace() {
        return false;
    }

    let mut previous = index;
    while previous > 0 && bytes[previous - 1].is_ascii_whitespace() {
        previous -= 1;
    }

    previous == 0 || bytes[previous - 1] == b','
}

/// Format a PaymentChallenge as a WWW-Authenticate header value.
pub fn format_www_authenticate(challenge: &PaymentChallenge) -> Result<String, Error> {
    let mut parts = vec![
        format!("id=\"{}\"", escape_quoted_value(&challenge.id)?),
        format!("realm=\"{}\"", escape_quoted_value(&challenge.realm)?),
        format!(
            "method=\"{}\"",
            escape_quoted_value(challenge.method.as_str())?
        ),
        format!(
            "intent=\"{}\"",
            escape_quoted_value(challenge.intent.as_str())?
        ),
        format!(
            "request=\"{}\"",
            escape_quoted_value(challenge.request.raw())?
        ),
    ];

    if let Some(ref expires) = challenge.expires {
        parts.push(format!("expires=\"{}\"", escape_quoted_value(expires)?));
    }
    // description is already encoded inside the `request` payload —
    // don't duplicate it as a top-level header param (non-ASCII descriptions
    // like em-dashes would make the header value invalid).
    if let Some(ref digest) = challenge.digest {
        parts.push(format!("digest=\"{}\"", escape_quoted_value(digest)?));
    }
    if let Some(ref opaque) = challenge.opaque {
        parts.push(format!("opaque=\"{}\"", escape_quoted_value(opaque.raw())?));
    }

    Ok(format!("Payment {}", parts.join(", ")))
}

/// Format multiple challenges as WWW-Authenticate header values.
pub fn format_www_authenticate_many(challenges: &[PaymentChallenge]) -> Result<Vec<String>, Error> {
    challenges.iter().map(format_www_authenticate).collect()
}

/// Parse an Authorization header into a PaymentCredential.
pub fn parse_authorization(header: &str) -> Result<PaymentCredential, Error> {
    let payment_part = extract_payment_scheme(header)
        .ok_or_else(|| Error::Other("Expected 'Payment' scheme".into()))?;

    let token = payment_part.get(8..).unwrap_or("").trim();

    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::Other(format!(
            "Token exceeds maximum length of {MAX_TOKEN_LEN} bytes"
        )));
    }

    let decoded = base64url_decode(token)?;
    let credential: PaymentCredential = serde_json::from_slice(&decoded)
        .map_err(|e| Error::Other(format!("Invalid credential JSON: {e}")))?;

    Ok(credential)
}

/// Format a PaymentCredential as an Authorization header value.
///
/// Uses JCS (RFC 8785) canonicalization before base64url encoding
/// as required by the spec.
pub fn format_authorization(credential: &PaymentCredential) -> Result<String, Error> {
    let json = serde_json_canonicalizer::to_string(credential)
        .map_err(|e| Error::Other(format!("JCS serialization failed: {e}")))?;
    let encoded = base64url_encode(json.as_bytes());
    Ok(format!("Payment {encoded}"))
}

/// Parse a Payment-Receipt header into a Receipt.
pub fn parse_receipt(header: &str) -> Result<Receipt, Error> {
    let token = header.trim();
    if token.len() > MAX_TOKEN_LEN {
        return Err(Error::Other(format!(
            "Receipt exceeds maximum length of {MAX_TOKEN_LEN} bytes"
        )));
    }

    let decoded = base64url_decode(token)?;
    let receipt: Receipt = serde_json::from_slice(&decoded)
        .map_err(|e| Error::Other(format!("Invalid receipt JSON: {e}")))?;
    Ok(receipt)
}

/// Format a Receipt as a Payment-Receipt header value.
///
/// Uses JCS (RFC 8785) canonicalization before base64url encoding
/// as required by the spec.
pub fn format_receipt(receipt: &Receipt) -> Result<String, Error> {
    let json = serde_json_canonicalizer::to_string(receipt)
        .map_err(|e| Error::Other(format!("JCS serialization failed: {e}")))?;
    Ok(base64url_encode(json.as_bytes()))
}

/// Extract the `Payment` scheme from an Authorization header.
pub fn extract_payment_scheme(header: &str) -> Option<&str> {
    header.split(',').map(|s| s.trim()).find(|s| {
        s.len() >= 8
            && s.get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("payment "))
    })
}

// ── Private helpers ──

fn strip_payment_scheme(header: &str) -> Option<&str> {
    let header = header.trim_start();
    let scheme_len = PAYMENT_SCHEME.len();
    if header.len() >= scheme_len
        && header
            .get(..scheme_len)
            .is_some_and(|s| s.eq_ignore_ascii_case(PAYMENT_SCHEME))
    {
        header.get(scheme_len..)
    } else {
        None
    }
}

fn escape_quoted_value(s: &str) -> Result<String, Error> {
    if s.contains('\r') || s.contains('\n') {
        return Err(Error::Other(
            "Header value contains invalid CRLF characters".into(),
        ));
    }
    Ok(s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn require_param<'a>(params: &'a HashMap<String, String>, key: &str) -> Result<&'a String, Error> {
    params
        .get(key)
        .ok_or_else(|| Error::Other(format!("Missing '{key}' field")))
}

fn parse_auth_params(params_str: &str) -> Result<HashMap<String, String>, Error> {
    let mut params = HashMap::new();
    let chars: Vec<char> = params_str.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        while i < chars.len() && (chars[i].is_whitespace() || chars[i] == ',') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }

        let key_start = i;
        while i < chars.len() && chars[i] != '=' && !chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            while i < chars.len() && !chars[i].is_whitespace() && chars[i] != ',' {
                i += 1;
            }
            continue;
        }

        let key: String = chars[key_start..i].iter().collect();
        i += 1;

        if i >= chars.len() {
            break;
        }

        let value = if chars[i] == '"' {
            i += 1;
            let mut value = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    value.push(chars[i]);
                } else {
                    value.push(chars[i]);
                }
                i += 1;
            }
            if i < chars.len() {
                i += 1;
            }
            value
        } else {
            let value_start = i;
            while i < chars.len() && !chars[i].is_whitespace() && chars[i] != ',' {
                i += 1;
            }
            chars[value_start..i].iter().collect()
        };

        if params.contains_key(&key) {
            return Err(Error::Other(format!("Duplicate parameter: {key}")));
        }
        params.insert(key, value);
    }

    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::types::ReceiptStatus;

    fn test_challenge() -> PaymentChallenge {
        PaymentChallenge {
            id: "abc123".to_string(),
            realm: "api".to_string(),
            method: "solana".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "10000",
                "currency": "USDC"
            }))
            .unwrap(),
            expires: Some("2024-01-01T00:00:00Z".to_string()),
            description: None,
            digest: None,
            opaque: None,
        }
    }

    #[test]
    fn www_authenticate_roundtrip() {
        let challenge = test_challenge();
        let header = format_www_authenticate(&challenge).unwrap();
        let parsed = parse_www_authenticate(&header).unwrap();
        assert_eq!(parsed.id, "abc123");
        assert_eq!(parsed.realm, "api");
        assert_eq!(parsed.method.as_str(), "solana");
        assert_eq!(parsed.intent.as_str(), "charge");
    }

    #[test]
    fn authorization_roundtrip() {
        let challenge = test_challenge();
        let payload = serde_json::json!({"type": "transaction", "transaction": "base64tx"});
        let credential = PaymentCredential::new(challenge.to_echo(), payload);
        let header = format_authorization(&credential).unwrap();
        let parsed = parse_authorization(&header).unwrap();
        assert_eq!(parsed.challenge.id, "abc123");
    }

    #[test]
    fn receipt_roundtrip() {
        let receipt = Receipt {
            status: ReceiptStatus::Success,
            method: "solana".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "5UfDuX...".to_string(),
            challenge_id: "ch-test".to_string(),
        };
        let header = format_receipt(&receipt).unwrap();
        let parsed = parse_receipt(&header).unwrap();
        assert_eq!(parsed.reference, "5UfDuX...");
    }

    #[test]
    fn parse_rejects_non_payment() {
        assert!(parse_www_authenticate("Bearer realm=\"test\"").is_err());
    }

    #[test]
    fn parse_rejects_duplicate_params() {
        let header = r#"Payment id="a", realm="api", method="solana", intent="charge", request="e30", id="b""#;
        assert!(parse_www_authenticate(header).is_err());
    }

    #[test]
    fn extract_payment_scheme_mixed() {
        let header = "Bearer token123, Payment eyJhYmMi";
        let result = extract_payment_scheme(header);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Payment eyJhYmMi");
    }

    // ── parse_www_authenticate edge cases ──

    #[test]
    fn parse_rejects_empty_id() {
        let header =
            r#"Payment id="", realm="api", method="solana", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Empty 'id'"));
    }

    #[test]
    fn parse_rejects_uppercase_method() {
        let header =
            r#"Payment id="x", realm="api", method="SOLANA", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid method"));
    }

    #[test]
    fn parse_rejects_empty_method() {
        let header = r#"Payment id="x", realm="api", method="", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid method"));
    }

    #[test]
    fn parse_rejects_missing_request() {
        let header = r#"Payment id="x", realm="api", method="solana", intent="charge""#;
        let err = parse_www_authenticate(header);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Missing 'request'"));
    }

    #[test]
    fn parse_rejects_missing_realm() {
        let header = r#"Payment id="x", method="solana", intent="charge", request="e30""#;
        let err = parse_www_authenticate(header);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Missing 'realm'"));
    }

    #[test]
    fn parse_rejects_invalid_json_in_request() {
        // base64url of "not json"
        let bad_b64 = base64url_encode(b"not json");
        let header = format!(
            r#"Payment id="x", realm="api", method="solana", intent="charge", request="{bad_b64}""#
        );
        let err = parse_www_authenticate(&header);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("Invalid JSON"));
    }

    #[test]
    fn parse_with_tab_after_scheme() {
        // Tab instead of space after "Payment"
        let header = "Payment\tid=\"x\", realm=\"api\", method=\"solana\", intent=\"charge\", request=\"e30\"";
        let parsed = parse_www_authenticate(header);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().id, "x");
    }

    #[test]
    fn parse_rejects_no_space_after_scheme() {
        let header = "Paymentid=\"x\"";
        assert!(parse_www_authenticate(header).is_err());
    }

    #[test]
    fn parse_preserves_optional_fields() {
        let opaque_b64 = base64url_encode(b"{\"nonce\":\"abc\"}");
        let header = format!(
            r#"Payment id="x", realm="api", method="solana", intent="charge", request="e30", expires="2099-01-01T00:00:00Z", description="Test payment", digest="sha-256=abc", opaque="{opaque_b64}""#
        );
        let parsed = parse_www_authenticate(&header).unwrap();
        assert_eq!(parsed.expires.as_deref(), Some("2099-01-01T00:00:00Z"));
        assert_eq!(parsed.description.as_deref(), Some("Test payment"));
        assert_eq!(parsed.digest.as_deref(), Some("sha-256=abc"));
        assert!(parsed.opaque.is_some());
        assert_eq!(parsed.opaque.unwrap().raw(), opaque_b64);
    }

    // ── parse_www_authenticate_all ──

    #[test]
    fn parse_all_filters_non_payment() {
        let headers = vec![
            "Bearer token123",
            "Payment id=\"x\", realm=\"api\", method=\"solana\", intent=\"charge\", request=\"e30\"",
            "Digest qop=auth",
        ];
        let results = parse_www_authenticate_all(headers);
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[test]
    fn parse_all_empty() {
        let results = parse_www_authenticate_all(Vec::<&str>::new());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_all_multiple_payment_headers() {
        let h1 =
            "Payment id=\"a\", realm=\"r1\", method=\"solana\", intent=\"charge\", request=\"e30\"";
        let h2 =
            "Payment id=\"b\", realm=\"r2\", method=\"solana\", intent=\"charge\", request=\"e30\"";
        let results = parse_www_authenticate_all(vec![h1, h2]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().id, "a");
        assert_eq!(results[1].as_ref().unwrap().id, "b");
    }

    #[test]
    fn parse_all_merged_payment_header() {
        let header = concat!(
            "Payment id=\"a\", realm=\"r1\", method=\"solana\", intent=\"charge\", request=\"e30\", ",
            "Payment id=\"b\", realm=\"r2\", method=\"solana\", intent=\"charge\", request=\"e30\"",
        );

        let results = parse_www_authenticate_all(vec![header]);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().id, "a");
        assert_eq!(results[1].as_ref().unwrap().id, "b");
    }

    #[test]
    fn parse_all_merged_payment_header_ignores_payment_inside_quotes() {
        let header = concat!(
            "Payment id=\"a\", realm=\"api, Payment realm\", method=\"solana\", intent=\"charge\", request=\"e30\", ",
            "Payment id=\"b\", realm=\"r2\", method=\"solana\", intent=\"charge\", request=\"e30\"",
        );

        let results = parse_www_authenticate_all(vec![header]);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().realm, "api, Payment realm");
        assert_eq!(results[1].as_ref().unwrap().id, "b");
    }

    // ── format_www_authenticate edge cases ──

    #[test]
    fn format_with_all_optional_fields() {
        let opaque = Base64UrlJson::from_value(&serde_json::json!({"n": 1})).unwrap();
        let challenge = PaymentChallenge {
            id: "id1".to_string(),
            realm: "realm1".to_string(),
            method: "solana".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: Some("2099-01-01T00:00:00Z".to_string()),
            description: Some("Test".to_string()),
            digest: Some("sha-256=xyz".to_string()),
            opaque: Some(opaque),
        };
        let header = format_www_authenticate(&challenge).unwrap();
        assert!(header.contains("expires="));
        // description is no longer emitted (it's inside the request payload)
        assert!(!header.contains("description="));
        assert!(header.contains("digest="));
        assert!(header.contains("opaque="));
    }

    #[test]
    fn format_www_authenticate_many_empty() {
        let result = format_www_authenticate_many(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn format_www_authenticate_many_multiple() {
        let c1 = test_challenge();
        let mut c2 = test_challenge();
        c2.id = "def456".to_string();
        let result = format_www_authenticate_many(&[c1, c2]).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].contains("abc123"));
        assert!(result[1].contains("def456"));
    }

    // ── escape_quoted_value edge cases ──

    #[test]
    fn format_rejects_crlf_in_values() {
        let mut challenge = test_challenge();
        challenge.id = "bad\rid".to_string();
        assert!(format_www_authenticate(&challenge).is_err());
    }

    #[test]
    fn format_rejects_newline_in_values() {
        let mut challenge = test_challenge();
        challenge.realm = "bad\nrealm".to_string();
        assert!(format_www_authenticate(&challenge).is_err());
    }

    #[test]
    fn format_escapes_quotes_in_values() {
        let mut challenge = test_challenge();
        challenge.id = r#"id"with"quotes"#.to_string();
        let header = format_www_authenticate(&challenge).unwrap();
        assert!(header.contains(r#"id\"with\"quotes"#));
        // Roundtrip should work
        let parsed = parse_www_authenticate(&header).unwrap();
        assert_eq!(parsed.id, r#"id"with"quotes"#);
    }

    #[test]
    fn format_escapes_backslashes_in_values() {
        let mut challenge = test_challenge();
        challenge.id = r"id\with\backslash".to_string();
        let header = format_www_authenticate(&challenge).unwrap();
        let parsed = parse_www_authenticate(&header).unwrap();
        assert_eq!(parsed.id, r"id\with\backslash");
    }

    // ── parse_authorization edge cases ──

    #[test]
    fn parse_authorization_rejects_non_payment() {
        assert!(parse_authorization("Bearer abc123").is_err());
    }

    #[test]
    fn parse_authorization_rejects_oversized_token() {
        let huge = "a".repeat(MAX_TOKEN_LEN + 1);
        let header = format!("Payment {huge}");
        let err = parse_authorization(&header);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("exceeds maximum length"));
    }

    #[test]
    fn parse_authorization_rejects_invalid_base64() {
        assert!(parse_authorization("Payment @@@invalid@@@").is_err());
    }

    #[test]
    fn parse_authorization_rejects_invalid_json() {
        let bad = base64url_encode(b"not json");
        let header = format!("Payment {bad}");
        assert!(parse_authorization(&header).is_err());
    }

    // ── parse_receipt edge cases ──

    #[test]
    fn parse_receipt_rejects_oversized() {
        let huge = "a".repeat(MAX_TOKEN_LEN + 1);
        let err = parse_receipt(&huge);
        assert!(err.is_err());
        assert!(format!("{}", err.unwrap_err()).contains("exceeds maximum length"));
    }

    #[test]
    fn parse_receipt_rejects_invalid_json() {
        let bad = base64url_encode(b"not json");
        assert!(parse_receipt(&bad).is_err());
    }

    // ── extract_payment_scheme edge cases ──

    #[test]
    fn extract_payment_scheme_none_when_absent() {
        assert!(extract_payment_scheme("Bearer token123").is_none());
    }

    #[test]
    fn extract_payment_scheme_case_insensitive() {
        let result = extract_payment_scheme("payment abc123");
        assert!(result.is_some());
    }

    #[test]
    fn extract_payment_scheme_first_match() {
        let header = "Payment aaa, Payment bbb";
        let result = extract_payment_scheme(header);
        assert_eq!(result, Some("Payment aaa"));
    }

    // ── parse_auth_params edge cases ──

    #[test]
    fn parse_params_unquoted_values() {
        let header = "Payment id=abc123, realm=api, method=solana, intent=charge, request=e30";
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.id, "abc123");
    }

    #[test]
    fn parse_params_extra_whitespace() {
        let header = r#"Payment   id="x" ,  realm="api" ,  method="solana" ,  intent="charge" ,  request="e30""#;
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.id, "x");
    }

    #[test]
    fn parse_params_key_without_value_skipped() {
        // "badkey" has no = sign, should be skipped
        let header = r#"Payment id="x", badkey, realm="api", method="solana", intent="charge", request="e30""#;
        let parsed = parse_www_authenticate(header).unwrap();
        assert_eq!(parsed.id, "x");
    }
}
