//! The `RunnerResult` a testee returns for one vector, validated at the
//! process boundary exactly like `runnerResultSchema` in
//! `harness/src/conformance/contract-schema.ts` (`additionalProperties:
//! false` everywhere, so an over-typed result is a contract drift), plus the
//! two additive fields the Rust judge needs to verify builds:
//!
//! - `transaction`: the built base64 wire transaction (charge builds);
//! - `x402PaymentHeader`: the built base64 payment header (x402 builds).

use serde_json::{Map, Value};

use crate::case::RejectCode;

type Check = fn(&Value) -> bool;

fn is_string(v: &Value) -> bool {
    v.is_string()
}
fn is_bool(v: &Value) -> bool {
    v.is_boolean()
}
fn is_number(v: &Value) -> bool {
    v.is_number()
}
fn is_integer(v: &Value) -> bool {
    v.is_i64() || v.is_u64() || v.as_f64().is_some_and(|f| f.fract() == 0.0)
}
fn is_string_array(v: &Value) -> bool {
    v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
}
fn is_integer_array(v: &Value) -> bool {
    v.as_array().is_some_and(|a| a.iter().all(is_integer))
}

fn object(
    value: &Value,
    path: &str,
    required: &[&str],
    fields: &[(&str, Check)],
    errors: &mut Vec<String>,
) -> Option<Map<String, Value>> {
    let Some(obj) = value.as_object() else {
        errors.push(format!("{path} must be object"));
        return None;
    };
    for key in required {
        if !obj.contains_key(*key) {
            errors.push(format!("{path} must have required property '{key}'"));
        }
    }
    for (key, v) in obj {
        match fields.iter().find(|(name, _)| name == key) {
            Some((_, check)) => {
                if !check(v) {
                    errors.push(format!("{path}/{key} has the wrong type"));
                }
            }
            None if NESTED.contains(&key.as_str()) && path == "(root)" => {}
            None => errors.push(format!("{path} must NOT have additional property '{key}'")),
        }
    }
    Some(obj.clone())
}

const NESTED: [&str; 3] = ["transactionShape", "x402EnvelopeShape", "exactBytes"];

fn check_transfer(value: &Value, path: &str, errors: &mut Vec<String>) {
    if let Some(t) = object(
        value,
        path,
        &["kind", "amount"],
        &[
            ("kind", |v| matches!(v.as_str(), Some("spl" | "sol"))),
            ("destination", is_string),
            ("destinationOwner", is_string),
            ("mint", is_string),
            ("amount", is_string),
            ("decimals", is_integer),
            ("tokenProgram", is_string),
        ],
        errors,
    ) {
        let _ = t;
    }
}

/// Validate a runner result; `Err` lists every violation, like ajv
/// `allErrors`.
pub fn validate(result: &Value) -> Result<(), String> {
    let mut errors = Vec::new();
    let codes: Vec<&str> = RejectCode::ALL.iter().map(|c| c.as_str()).collect();
    let Some(root) = object(
        result,
        "(root)",
        &["id", "outcome"],
        &[
            ("id", is_string),
            ("outcome", |v| {
                matches!(v.as_str(), Some("accept" | "reject" | "unsupported-mode"))
            }),
            ("error", is_string),
            ("rejectCode", is_string),
            ("transaction", is_string),
            ("x402PaymentHeader", is_string),
        ],
        &mut errors,
    ) else {
        return Err(errors.join("; "));
    };
    if let Some(code) = root.get("rejectCode").and_then(Value::as_str) {
        if !codes.contains(&code) {
            errors.push("/rejectCode must be equal to one of the allowed values".into());
        }
    }
    if let Some(shape) = root.get("transactionShape") {
        if let Some(obj) = object(
            shape,
            "/transactionShape",
            &[],
            &[
                ("feePayer", is_string),
                ("transfers", |v| v.is_array()),
                ("forbiddenPrograms", is_string_array),
                ("maxComputeUnitLimit", is_integer),
                ("maxComputeUnitPrice", is_string),
                ("memo", is_string_array),
            ],
            &mut errors,
        ) {
            if let Some(transfers) = obj.get("transfers").and_then(Value::as_array) {
                for (i, t) in transfers.iter().enumerate() {
                    check_transfer(t, &format!("/transactionShape/transfers/{i}"), &mut errors);
                }
            }
        }
    }
    if let Some(shape) = root.get("x402EnvelopeShape") {
        object(
            shape,
            "/x402EnvelopeShape",
            &["x402Version", "hasAccepted", "payloadHasTransaction"],
            &[
                ("x402Version", is_number),
                ("scheme", is_string),
                ("network", is_string),
                ("hasAccepted", is_bool),
                ("payloadHasTransaction", is_bool),
                ("acceptedScheme", is_string),
                ("acceptedNetwork", is_string),
                ("acceptedAsset", is_string),
                ("acceptedPayTo", is_string),
                ("acceptedAmount", is_string),
                ("hasExtensions", is_bool),
                ("hasPaymentIdentifier", is_bool),
                ("paymentIdentifierRequired", is_bool),
                ("paymentIdentifierId", is_string),
                ("extensionKeys", is_string_array),
            ],
            &mut errors,
        );
    }
    if let Some(bytes) = root.get("exactBytes") {
        object(
            bytes,
            "/exactBytes",
            &[],
            &[
                ("canonicalJson", is_string),
                ("base64Url", is_string),
                ("bytes", is_integer_array),
            ],
            &mut errors,
        );
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn accepts_well_formed_results() {
        for ok in [
            json!({"id": "a", "outcome": "accept", "transactionShape": {"feePayer": "x", "transfers": [{"kind": "sol", "amount": "1"}]}, "transaction": "AQ=="}),
            json!({"id": "a", "outcome": "reject", "error": "boom", "rejectCode": "amount-mismatch"}),
            json!({"id": "a", "outcome": "unsupported-mode", "error": "unsupported-mode: x"}),
            json!({"id": "a", "outcome": "accept", "exactBytes": {"bytes": [1, 2], "base64Url": "AQI"}}),
            json!({"id": "a", "outcome": "accept", "x402EnvelopeShape": {"x402Version": 2, "hasAccepted": true, "payloadHasTransaction": true}, "x402PaymentHeader": "e30="}),
        ] {
            validate(&ok).unwrap();
        }
    }

    #[test]
    fn rejects_drift() {
        for (bad, why) in [
            (json!({"outcome": "accept"}), "required property 'id'"),
            (json!({"id": "a", "outcome": "maybe"}), "/outcome"),
            (
                json!({"id": "a", "outcome": "accept", "expected": true}),
                "additional property 'expected'",
            ),
            (
                json!({"id": "a", "outcome": "reject", "rejectCode": "nope"}),
                "rejectCode",
            ),
            (
                json!({"id": "a", "outcome": "accept", "transactionShape": {"transfers": [{"kind": "sol", "amount": 1}]}}),
                "transfers/0/amount",
            ),
            (
                json!({"id": "a", "outcome": "accept", "x402EnvelopeShape": {"x402Version": 2}}),
                "hasAccepted",
            ),
            (
                json!({"id": "a", "outcome": "accept", "exactBytes": {"hex": "00"}}),
                "additional property 'hex'",
            ),
        ] {
            let err = validate(&bad).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
    }
}
