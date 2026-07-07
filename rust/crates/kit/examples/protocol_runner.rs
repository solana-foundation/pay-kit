//! mpp-protocol conformance runner for the Rust SDK.
//!
//! Speaks the canonical `tempoxyz/mpp-tools` adapter ABI used by the
//! harness's mpp-protocol conformance layer (`harness/src/protocol/`):
//! reads one `{ "op": ..., "input": ... }` request as JSON on stdin and
//! writes one response as JSON on stdout:
//!
//!   { "success": true,  "result": <op-specific> }
//!   { "success": false, "error": "<msg>", "error_type": "<type>" }
//!
//! Each operation maps to the Rust SDK's existing protocol-core functions
//! (`solana_pay_kit::mpp::protocol::core`): the `Payment` HTTP-auth header codec
//! (challenge / credential / receipt), base64url, and the challenge-id
//! HMAC. This is the Rust counterpart to the TypeScript reference runner at
//! `harness/src/protocol/runners/typescript.ts`; the two must agree on the
//! canonical vectors vendored under `harness/vectors/mpp-protocol/`.
//!
//! Run directly:
//!   echo '{"op":"base64url.encode","input":{"text":"a"}}' \
//!     | cargo run -q -p solana-mpp --example protocol_runner

use std::io::Read;

use serde_json::{json, Map, Value};
use solana_pay_kit::mpp::protocol::core::{
    base64url_decode, base64url_encode, compute_challenge_id, format_authorization, format_receipt,
    format_www_authenticate, parse_authorization, parse_receipt, parse_www_authenticate,
    Base64UrlJson, PaymentChallenge, PaymentCredential, ReceiptKind,
};

/// Canonical adapter-ABI response shape.
enum Outcome {
    Ok(Value),
    /// (error message, canonical error_type)
    Err(String, &'static str),
}

fn main() {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        emit(Outcome::Err("failed to read stdin".into(), "runner_error"));
        return;
    }

    let request: Value = match serde_json::from_str(raw.trim()) {
        Ok(v) => v,
        Err(e) => {
            emit(Outcome::Err(
                format!("invalid request JSON: {e}"),
                "runner_error",
            ));
            return;
        }
    };

    let op = request.get("op").and_then(Value::as_str).unwrap_or("");
    let input = request.get("input").cloned().unwrap_or(Value::Null);

    emit(dispatch(op, &input));
}

fn dispatch(op: &str, input: &Value) -> Outcome {
    match op {
        "challenge.parse" => challenge_parse(input),
        "challenge.format" => challenge_format(input),
        "credential.parse" => credential_parse(input),
        "credential.format" => credential_format(input),
        "receipt.parse" => receipt_parse(input),
        "receipt.format" => receipt_format(input),
        "base64url.encode" => base64url_encode_op(input),
        "base64url.decode" => base64url_decode_op(input),
        "challenge.id" => challenge_id(input),
        other => Outcome::Err(
            format!("operation not implemented by the Rust SDK: {other}"),
            "unsupported_operation",
        ),
    }
}

// ── helpers ──

fn header_field(input: &Value) -> Result<String, Outcome> {
    input
        .get("header")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Outcome::Err("missing 'header' field".into(), "runner_error"))
}

fn text_field(input: &Value) -> Result<String, Outcome> {
    input
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Outcome::Err("missing 'text' field".into(), "runner_error"))
}

/// Canonicalize a request JSON value into the pay-kit base64url(JCS) shape,
/// matching `Base64UrlJson::from_value` used across the protocol core.
fn request_to_b64(request: &Value) -> Result<Base64UrlJson, Outcome> {
    Base64UrlJson::from_value(request).map_err(|e| {
        Outcome::Err(
            format!("request canonicalization failed: {e}"),
            "format_error",
        )
    })
}

/// Decode a base64url-JSON slot into a JSON value for the canonical object
/// shape (the canonical vectors carry `request` as a decoded object, while
/// the Rust struct keeps it as the raw base64url string).
fn b64_to_value(b64: &Base64UrlJson) -> Result<Value, Outcome> {
    b64.decode_value().map_err(|e| {
        Outcome::Err(
            format!("base64url request decode failed: {e}"),
            "parse_error",
        )
    })
}

// ── challenge ──

fn challenge_parse(input: &Value) -> Outcome {
    let header = match header_field(input) {
        Ok(h) => h,
        Err(o) => return o,
    };
    let challenge = match parse_www_authenticate(&header) {
        Ok(c) => c,
        Err(e) => return Outcome::Err(e.to_string(), "parse_error"),
    };
    match challenge_to_object(&challenge) {
        Ok(obj) => Outcome::Ok(obj),
        Err(o) => o,
    }
}

fn challenge_to_object(c: &PaymentChallenge) -> Result<Value, Outcome> {
    let mut obj = Map::new();
    obj.insert("id".into(), json!(c.id));
    obj.insert("realm".into(), json!(c.realm));
    obj.insert("method".into(), json!(c.method.as_str()));
    obj.insert("intent".into(), json!(c.intent.as_str()));
    obj.insert("request".into(), b64_to_value(&c.request)?);
    if let Some(ref e) = c.expires {
        obj.insert("expires".into(), json!(e));
    }
    if let Some(ref d) = c.description {
        obj.insert("description".into(), json!(d));
    }
    if let Some(ref d) = c.digest {
        obj.insert("digest".into(), json!(d));
    }
    if let Some(ref o) = c.opaque {
        // opaque carries an opaque base64url payload; surface the raw slot.
        obj.insert("opaque".into(), json!(o.raw()));
    }
    Ok(Value::Object(obj))
}

fn challenge_format(input: &Value) -> Outcome {
    let challenge = match object_to_challenge(input) {
        Ok(c) => c,
        Err(o) => return o,
    };
    match format_www_authenticate(&challenge) {
        Ok(header) => Outcome::Ok(json!({ "header": header })),
        Err(e) => Outcome::Err(e.to_string(), "format_error"),
    }
}

fn object_to_challenge(input: &Value) -> Result<PaymentChallenge, Outcome> {
    let obj = input
        .as_object()
        .ok_or_else(|| Outcome::Err("challenge object expected".into(), "format_error"))?;

    let id = str_field(obj, "id")?;
    let realm = str_field(obj, "realm")?;
    let method = str_field(obj, "method")?;
    let intent = str_field(obj, "intent")?;
    let request_val = obj
        .get("request")
        .cloned()
        .ok_or_else(|| Outcome::Err("missing 'request' field".into(), "format_error"))?;
    let request = request_to_b64(&request_val)?;

    let opaque = match obj.get("opaque") {
        Some(Value::String(s)) => Some(Base64UrlJson::from_raw(s.clone())),
        Some(other) => Some(request_to_b64(other)?),
        None => None,
    };

    Ok(PaymentChallenge {
        id,
        realm,
        method: method.into(),
        intent: intent.into(),
        request,
        expires: opt_str(obj, "expires"),
        description: opt_str(obj, "description"),
        digest: opt_str(obj, "digest"),
        opaque,
    })
}

// ── credential ──

fn credential_parse(input: &Value) -> Outcome {
    let header = match header_field(input) {
        Ok(h) => h,
        Err(o) => return o,
    };
    match parse_authorization(&header) {
        // The driver's credential normalization decodes `challenge.request`
        // from base64url on both sides, so serializing the SDK struct as-is
        // (request kept as the raw base64url string) compares equal.
        Ok(cred) => match serde_json::to_value(&cred) {
            Ok(v) => Outcome::Ok(v),
            Err(e) => Outcome::Err(
                format!("credential serialization failed: {e}"),
                "parse_error",
            ),
        },
        Err(e) => Outcome::Err(e.to_string(), "parse_error"),
    }
}

fn credential_format(input: &Value) -> Outcome {
    let cred = match object_to_credential(input) {
        Ok(c) => c,
        Err(o) => return o,
    };
    match format_authorization(&cred) {
        Ok(header) => Outcome::Ok(json!({ "header": header })),
        Err(e) => Outcome::Err(e.to_string(), "format_error"),
    }
}

fn object_to_credential(input: &Value) -> Result<PaymentCredential, Outcome> {
    let obj = input
        .as_object()
        .ok_or_else(|| Outcome::Err("credential object expected".into(), "format_error"))?;

    let challenge_val = obj
        .get("challenge")
        .ok_or_else(|| Outcome::Err("missing 'challenge' field".into(), "format_error"))?;
    let challenge = object_to_challenge(challenge_val)?;

    let payload = obj.get("payload").cloned().unwrap_or(Value::Null);

    let mut cred = PaymentCredential::new(challenge.to_echo(), payload);
    if let Some(Value::String(s)) = obj.get("source") {
        cred.source = Some(s.clone());
    }
    Ok(cred)
}

// ── receipt ──

fn receipt_parse(input: &Value) -> Outcome {
    let header = match header_field(input) {
        Ok(h) => h,
        Err(o) => return o,
    };
    match parse_receipt(&header) {
        Ok(kind) => match serde_json::to_value(receipt_kind_value(&kind)) {
            Ok(v) => Outcome::Ok(v),
            Err(e) => Outcome::Err(format!("receipt serialization failed: {e}"), "parse_error"),
        },
        Err(e) => Outcome::Err(e.to_string(), "parse_error"),
    }
}

/// Flatten a ReceiptKind to its canonical wire object (base fields plus any
/// subscription extension fields), matching `format_receipt`'s JCS shape.
fn receipt_kind_value(kind: &ReceiptKind) -> Value {
    serde_json::to_value(kind).unwrap_or(Value::Null)
}

fn receipt_format(input: &Value) -> Outcome {
    let kind: ReceiptKind = match serde_json::from_value(input.clone()) {
        Ok(k) => k,
        Err(e) => return Outcome::Err(format!("invalid receipt object: {e}"), "format_error"),
    };
    match format_receipt(&kind) {
        Ok(header) => Outcome::Ok(json!({ "header": header })),
        Err(e) => Outcome::Err(e.to_string(), "format_error"),
    }
}

// ── base64url ──

fn base64url_encode_op(input: &Value) -> Outcome {
    let text = match text_field(input) {
        Ok(t) => t,
        Err(o) => return o,
    };
    Outcome::Ok(json!({ "text": base64url_encode(text.as_bytes()) }))
}

fn base64url_decode_op(input: &Value) -> Outcome {
    let text = match text_field(input) {
        Ok(t) => t,
        Err(o) => return o,
    };
    match base64url_decode(&text) {
        Ok(bytes) => match String::from_utf8(bytes) {
            // Canonical base64url.decode yields UTF-8 text.
            Ok(s) => Outcome::Ok(json!({ "text": s })),
            Err(e) => Outcome::Err(
                format!("decoded bytes are not UTF-8: {e}"),
                "encoding_error",
            ),
        },
        Err(e) => Outcome::Err(e.to_string(), "encoding_error"),
    }
}

// ── challenge.id ──

fn challenge_id(input: &Value) -> Outcome {
    let obj = match input.as_object() {
        Some(o) => o,
        None => {
            return Outcome::Err(
                "challenge.id input object expected".into(),
                "generation_error",
            )
        }
    };

    let secret = match obj.get("secretKey").and_then(Value::as_str) {
        Some(s) => s,
        None => return Outcome::Err("missing 'secretKey' field".into(), "generation_error"),
    };
    let realm = obj.get("realm").and_then(Value::as_str).unwrap_or("");
    let method = obj.get("method").and_then(Value::as_str).unwrap_or("");
    let intent = obj.get("intent").and_then(Value::as_str).unwrap_or("");

    // The HMAC binds the request as base64url(JCS canonical JSON), matching
    // the pay-kit/mppx request encoding. The canonical vectors pass `request`
    // as a decoded object, so canonicalize it here.
    let request_val = obj.get("request").cloned().unwrap_or_else(|| json!({}));
    let request_b64 = match request_to_b64(&request_val) {
        Ok(b) => b,
        Err(_) => {
            return Outcome::Err("request canonicalization failed".into(), "generation_error")
        }
    };

    // `description` is intentionally NOT part of the HMAC. `opaque` is fed as
    // the already-serialized pipe-slot string, exactly like the canonical ABI.
    let expires = obj.get("expires").and_then(Value::as_str);
    let digest = obj.get("digest").and_then(Value::as_str);
    let opaque = obj.get("opaque").and_then(Value::as_str);

    let id = compute_challenge_id(
        secret,
        realm,
        method,
        intent,
        request_b64.raw(),
        expires,
        digest,
        opaque,
    );
    Outcome::Ok(json!({ "id": id }))
}

// ── small field helpers ──

fn str_field(obj: &Map<String, Value>, key: &str) -> Result<String, Outcome> {
    obj.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Outcome::Err(format!("missing '{key}' field"), "format_error"))
}

fn opt_str(obj: &Map<String, Value>, key: &str) -> Option<String> {
    obj.get(key).and_then(Value::as_str).map(str::to_string)
}

fn emit(outcome: Outcome) {
    let value = match outcome {
        Outcome::Ok(result) => json!({ "success": true, "result": result }),
        Outcome::Err(error, error_type) => {
            json!({ "success": false, "error": error, "error_type": error_type })
        }
    };
    println!("{value}");
}
