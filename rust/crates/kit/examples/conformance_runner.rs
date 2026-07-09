//! x402 exact conformance-vector runner for the Rust SDK.
//!
//! The harness sends one vector as JSON on stdin and expects one `RunnerResult`
//! JSON object on stdout. Envelope modes use the Rust x402 wire types, while
//! `verify-x402-transaction` decodes the supplied transaction and calls the
//! production exact verifier directly.

use std::{io::Read, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use solana_pay_kit::{
    core::payment_channels::decode_transaction,
    mpp::protocol::core::{
        base64url_decode, base64url_encode, compute_challenge_id, Base64UrlJson,
    },
    x402::{
        protocol::schemes::exact::{
            caip2_network_for_cluster, verify_exact_versioned_transaction, PaymentExtensions,
            PaymentProof, PaymentRequirements, PaymentSignatureEnvelope, EXACT_SCHEME,
            SOLANA_DEVNET,
        },
        Error, X402_VERSION_V1, X402_VERSION_V2,
    },
};
use solana_pubkey::Pubkey;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    id: String,
    intent: String,
    mode: String,
    input: VectorInput,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct VectorInput {
    #[serde(rename = "x402Version")]
    x402_version: Option<u64>,
    x402_offer: Option<Value>,
    x402_pinned_transaction: Option<String>,
    x402_advertised_extensions: Option<Value>,
    x402_payment_identifier_id: Option<String>,
    x402_payment_header: Option<String>,
    x402_server_network: Option<String>,
    x402_server_recipient: Option<String>,
    x402_server_currency: Option<String>,
    x402_server_amount: Option<String>,
    x402_server_requires_payment_identifier: bool,
    transaction: Option<String>,
    x402_exact_requirement: Option<Value>,
    x402_exact_managed_signers: Vec<String>,
    value: Option<Value>,
    encode_base64_url: Option<EncodeBase64Url>,
    challenge_id: Option<ChallengeId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncodeBase64Url {
    hex_bytes: Option<String>,
    utf8: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeId {
    secret_key: String,
    realm: String,
    method: String,
    intent: String,
    request: String,
    expires: Option<String>,
    digest: Option<String>,
    opaque: Option<String>,
}

enum RunnerError {
    Rejected {
        message: String,
        reject_code: Option<&'static str>,
    },
    Exact(String),
}

impl RunnerError {
    fn rejected(message: impl Into<String>) -> Self {
        Self::Rejected {
            message: message.into(),
            reject_code: Some("invalid-payload"),
        }
    }

    fn coded(message: impl Into<String>, reject_code: &'static str) -> Self {
        Self::Rejected {
            message: message.into(),
            reject_code: Some(reject_code),
        }
    }
}

fn main() {
    let result = match read_vector() {
        Ok(vector) => {
            let id = vector.id.clone();
            match run_vector(vector) {
                Ok(result) => result,
                Err(error) => reject(&id, error),
            }
        }
        Err(error) => reject("", error),
    };
    println!("{result}");
}

fn read_vector() -> Result<Vector, RunnerError> {
    let mut stdin = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|error| RunnerError::rejected(format!("failed to read stdin: {error}")))?;
    serde_json::from_str(&stdin)
        .map_err(|error| RunnerError::rejected(format!("invalid conformance vector: {error}")))
}

fn run_vector(vector: Vector) -> Result<Value, RunnerError> {
    if vector.mode == "canonical-bytes" {
        return accept(&vector.id, None, Some(canonical_bytes(&vector.input)?));
    }

    if vector.intent != "x402-exact" {
        return Ok(json!({
            "id": vector.id,
            "language": "rust",
            "outcome": "unsupported-mode",
        }));
    }

    let result = match vector.mode.as_str() {
        "build-transaction" => {
            let envelope = build_envelope(&vector.input)?;
            accept(&vector.id, Some(envelope_shape(&envelope)), None)?
        }
        "verify-transaction" => {
            let envelope = verify_envelope(&vector.input)?;
            accept(&vector.id, Some(envelope_shape(&envelope)), None)?
        }
        "verify-x402-transaction" => {
            verify_exact_transaction(&vector.input)?;
            accept(&vector.id, None, None)?
        }
        _ => json!({
            "id": vector.id,
            "language": "rust",
            "outcome": "unsupported-mode",
        }),
    };

    Ok(result)
}

fn accept(
    id: &str,
    envelope_shape: Option<Value>,
    exact_bytes: Option<Value>,
) -> Result<Value, RunnerError> {
    let mut result = Map::new();
    result.insert("id".to_string(), Value::String(id.to_string()));
    result.insert("language".to_string(), Value::String("rust".to_string()));
    result.insert("outcome".to_string(), Value::String("accept".to_string()));
    if let Some(shape) = envelope_shape {
        result.insert("x402EnvelopeShape".to_string(), shape);
    }
    if let Some(exact_bytes) = exact_bytes {
        result.insert("exactBytes".to_string(), exact_bytes);
    }
    Ok(Value::Object(result))
}

fn reject(id: &str, error: RunnerError) -> Value {
    match error {
        RunnerError::Rejected {
            message,
            reject_code,
        } => {
            let mut result = Map::new();
            result.insert("id".to_string(), Value::String(id.to_string()));
            result.insert("language".to_string(), Value::String("rust".to_string()));
            result.insert("outcome".to_string(), Value::String("reject".to_string()));
            result.insert("error".to_string(), Value::String(message));
            if let Some(reject_code) = reject_code {
                result.insert(
                    "rejectCode".to_string(),
                    Value::String(reject_code.to_string()),
                );
            }
            Value::Object(result)
        }
        RunnerError::Exact(message) => json!({
            "id": id,
            "language": "rust",
            "outcome": "reject",
            "error": message,
            "x402ExactRejectCode": message,
        }),
    }
}

fn build_envelope(input: &VectorInput) -> Result<PaymentSignatureEnvelope, RunnerError> {
    let offer = normalized_offer(
        input
            .x402_offer
            .as_ref()
            .ok_or_else(|| RunnerError::rejected("missing input.x402Offer"))?,
    )?;
    let transaction = input
        .x402_pinned_transaction
        .clone()
        .ok_or_else(|| RunnerError::rejected("missing input.x402PinnedTransaction"))?;

    match input.x402_version.unwrap_or(X402_VERSION_V2) {
        X402_VERSION_V1 => Ok(PaymentSignatureEnvelope {
            scheme: Some(EXACT_SCHEME.to_string()),
            network: Some(v1_network(offer_string(&offer, "network")?)),
            x402_version: X402_VERSION_V1,
            accepted: None,
            resource: None,
            payload: PaymentProof::Transaction { transaction },
            extensions: None,
        }),
        X402_VERSION_V2 => {
            let mut extensions = PaymentExtensions::echoing(
                input.x402_advertised_extensions.as_ref(),
            )
            .map_err(|error| RunnerError::rejected(format!("invalid extensions: {error}")))?;
            if let Some(current) = extensions.take() {
                let current = if current.requires_payment_identifier() {
                    current.with_payment_identifier_id(
                        input
                            .x402_payment_identifier_id
                            .clone()
                            .unwrap_or_else(solana_pay_kit::x402::protocol::schemes::exact::generate_payment_identifier_id),
                    )
                } else {
                    current
                };
                extensions = (!current.is_empty()).then_some(current);
            }

            Ok(PaymentSignatureEnvelope {
                scheme: None,
                network: None,
                x402_version: X402_VERSION_V2,
                accepted: Some(offer),
                resource: None,
                payload: PaymentProof::Transaction { transaction },
                extensions,
            })
        }
        version => Err(RunnerError::coded(
            format!("unsupported x402 version {version}"),
            "unsupported-version",
        )),
    }
}

fn verify_envelope(input: &VectorInput) -> Result<PaymentSignatureEnvelope, RunnerError> {
    let header = input
        .x402_payment_header
        .as_deref()
        .ok_or_else(|| RunnerError::rejected("missing input.x402PaymentHeader"))?;
    let decoded = STANDARD
        .decode(header)
        .map_err(|error| RunnerError::rejected(format!("invalid payment header: {error}")))?;
    let envelope: PaymentSignatureEnvelope = serde_json::from_slice(&decoded)
        .map_err(|error| RunnerError::rejected(format!("invalid payment envelope: {error}")))?;
    let server_network = input
        .x402_server_network
        .as_deref()
        .ok_or_else(|| RunnerError::rejected("missing input.x402ServerNetwork"))?;
    let expected_network = caip2_network_for_cluster(server_network);

    match envelope.x402_version {
        X402_VERSION_V1 => {
            if envelope.scheme.as_deref() != Some(EXACT_SCHEME) {
                return Err(RunnerError::rejected("v1 envelope has an invalid scheme"));
            }
            let network = envelope
                .network
                .as_deref()
                .ok_or_else(|| RunnerError::rejected("v1 envelope is missing network"))?;
            if caip2_network_for_cluster(network) != expected_network {
                return Err(RunnerError::coded("v1 network mismatch", "wrong-network"));
            }
        }
        X402_VERSION_V2 => {
            let accepted = envelope
                .accepted
                .as_ref()
                .ok_or_else(|| RunnerError::rejected("v2 envelope is missing accepted"))?;
            let requirement: PaymentRequirements = serde_json::from_value(accepted.clone())
                .map_err(|error| {
                    RunnerError::rejected(format!("invalid accepted offer: {error}"))
                })?;
            if requirement.network != expected_network {
                return Err(RunnerError::coded("v2 network mismatch", "wrong-network"));
            }
            check_server_field(
                &requirement.recipient,
                input.x402_server_recipient.as_deref(),
                "recipient",
            )?;
            check_server_field(
                &requirement.currency,
                input.x402_server_currency.as_deref(),
                "currency",
            )?;
            check_server_field(
                &requirement.amount,
                input.x402_server_amount.as_deref(),
                "amount",
            )?;

            if input.x402_server_requires_payment_identifier
                && !envelope
                    .extensions
                    .as_ref()
                    .and_then(|extensions| extensions.payment_identifier.as_ref())
                    .and_then(|identifier| identifier.info.id.as_deref())
                    .is_some_and(valid_payment_identifier)
            {
                return Err(RunnerError::coded(
                    "payment identifier is required",
                    "payment-identifier-required",
                ));
            }
        }
        version => {
            return Err(RunnerError::coded(
                format!("unsupported x402 version {version}"),
                "unsupported-version",
            ));
        }
    }

    Ok(envelope)
}

fn verify_exact_transaction(input: &VectorInput) -> Result<(), RunnerError> {
    let transaction = input.transaction.as_deref().ok_or_else(|| {
        RunnerError::Exact("invalid_exact_svm_payload_transaction_could_not_be_decoded".to_string())
    })?;
    let requirement: PaymentRequirements =
        serde_json::from_value(input.x402_exact_requirement.clone().ok_or_else(|| {
            RunnerError::Exact("invalid_exact_svm_payload_no_transfer_instruction".to_string())
        })?)
        .map_err(|_| {
            RunnerError::Exact("invalid_exact_svm_payload_no_transfer_instruction".to_string())
        })?;
    let managed_signers = input
        .x402_exact_managed_signers
        .iter()
        .map(|signer| Pubkey::from_str(signer))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            RunnerError::Exact("invalid_exact_svm_payload_no_transfer_instruction".to_string())
        })?;
    let transaction = decode_transaction(transaction).map_err(|_| {
        RunnerError::Exact("invalid_exact_svm_payload_transaction_could_not_be_decoded".to_string())
    })?;

    verify_exact_versioned_transaction(&transaction, &requirement, &managed_signers)
        .map_err(exact_error)?;
    Ok(())
}

fn exact_error(error: Error) -> RunnerError {
    match error {
        Error::Other(code) if code.starts_with("invalid_exact_svm_payload_") => {
            RunnerError::Exact(code)
        }
        error => RunnerError::Exact(error.to_string()),
    }
}

fn canonical_bytes(input: &VectorInput) -> Result<Value, RunnerError> {
    let mut exact_bytes = Map::new();
    let mut handled = false;

    if let Some(value) = &input.value {
        let encoded = Base64UrlJson::from_value(value).map_err(|error| {
            RunnerError::rejected(format!("JCS canonicalization failed: {error}"))
        })?;
        let canonical_json =
            String::from_utf8(base64url_decode(encoded.raw()).map_err(|error| {
                RunnerError::rejected(format!("JCS base64url decoding failed: {error}"))
            })?)
            .map_err(|error| RunnerError::rejected(format!("JCS output is not UTF-8: {error}")))?;
        exact_bytes.insert("canonicalJson".to_string(), Value::String(canonical_json));
        exact_bytes.insert(
            "base64Url".to_string(),
            Value::String(encoded.raw().to_string()),
        );
        handled = true;
    }

    if let Some(input) = &input.encode_base64_url {
        let (bytes, include_bytes) = match (&input.hex_bytes, &input.utf8) {
            (Some(hex), _) => (decode_hex(hex)?, true),
            (None, Some(utf8)) => (utf8.as_bytes().to_vec(), false),
            (None, None) => {
                return Err(RunnerError::rejected(
                    "encodeBase64Url requires hexBytes or utf8",
                ));
            }
        };
        exact_bytes.insert(
            "base64Url".to_string(),
            Value::String(base64url_encode(&bytes)),
        );
        if include_bytes {
            exact_bytes.insert(
                "bytes".to_string(),
                Value::Array(bytes.into_iter().map(Value::from).collect()),
            );
        }
        handled = true;
    }

    if let Some(challenge) = &input.challenge_id {
        exact_bytes.insert(
            "base64Url".to_string(),
            Value::String(compute_challenge_id(
                &challenge.secret_key,
                &challenge.realm,
                &challenge.method,
                &challenge.intent,
                &challenge.request,
                challenge.expires.as_deref(),
                challenge.digest.as_deref(),
                challenge.opaque.as_deref(),
            )),
        );
        handled = true;
    }

    if !handled {
        return Err(RunnerError::rejected(
            "canonical-bytes vector has no supported input",
        ));
    }

    Ok(Value::Object(exact_bytes))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, RunnerError> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(RunnerError::rejected("hexBytes must have an even length"));
    }

    bytes
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, RunnerError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RunnerError::rejected(
            "hexBytes contains a non-hex character",
        )),
    }
}

fn normalized_offer(offer: &Value) -> Result<Value, RunnerError> {
    let offer = offer
        .as_object()
        .ok_or_else(|| RunnerError::rejected("input.x402Offer must be an object"))?;
    let mut normalized = Map::new();
    normalized.insert(
        "scheme".to_string(),
        Value::String(
            offer
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or(EXACT_SCHEME)
                .to_string(),
        ),
    );
    for field in ["network", "amount", "asset", "payTo"] {
        normalized.insert(
            field.to_string(),
            Value::String(
                offer
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or_else(|| RunnerError::rejected(format!("x402Offer is missing {field}")))?
                    .to_string(),
            ),
        );
    }
    normalized.insert(
        "maxTimeoutSeconds".to_string(),
        Value::from(
            offer
                .get("maxTimeoutSeconds")
                .and_then(Value::as_u64)
                .unwrap_or(300),
        ),
    );
    normalized.insert(
        "extra".to_string(),
        offer
            .get("extra")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new())),
    );
    Ok(Value::Object(normalized))
}

fn envelope_shape(envelope: &PaymentSignatureEnvelope) -> Value {
    let mut shape = Map::new();
    shape.insert(
        "x402Version".to_string(),
        Value::from(envelope.x402_version),
    );
    shape.insert(
        "hasAccepted".to_string(),
        Value::Bool(envelope.accepted.is_some()),
    );
    let payload_has_transaction = matches!(
        &envelope.payload,
        PaymentProof::Transaction { transaction } if !transaction.is_empty()
    );
    shape.insert(
        "payloadHasTransaction".to_string(),
        Value::Bool(payload_has_transaction),
    );
    if let Some(scheme) = &envelope.scheme {
        shape.insert("scheme".to_string(), Value::String(scheme.clone()));
    }
    if let Some(network) = &envelope.network {
        shape.insert("network".to_string(), Value::String(network.clone()));
    }
    if let Some(accepted) = envelope.accepted.as_ref().and_then(Value::as_object) {
        for (field, output) in [
            ("scheme", "acceptedScheme"),
            ("network", "acceptedNetwork"),
            ("asset", "acceptedAsset"),
            ("payTo", "acceptedPayTo"),
            ("amount", "acceptedAmount"),
        ] {
            if let Some(value) = accepted.get(field).and_then(Value::as_str) {
                shape.insert(output.to_string(), Value::String(value.to_string()));
            }
        }
    }

    let extensions = envelope
        .extensions
        .as_ref()
        .filter(|extensions| !extensions.is_empty());
    shape.insert(
        "hasExtensions".to_string(),
        Value::Bool(extensions.is_some()),
    );
    shape.insert(
        "hasPaymentIdentifier".to_string(),
        Value::Bool(
            extensions
                .and_then(|extensions| extensions.payment_identifier.as_ref())
                .is_some(),
        ),
    );
    let mut extension_keys = extensions
        .map(|extensions| {
            let mut keys = extensions.other.keys().cloned().collect::<Vec<_>>();
            if extensions.payment_identifier.is_some() {
                keys.push("payment-identifier".to_string());
            }
            keys.sort();
            keys
        })
        .unwrap_or_default();
    extension_keys.sort();
    shape.insert(
        "extensionKeys".to_string(),
        Value::Array(extension_keys.into_iter().map(Value::String).collect()),
    );
    if let Some(identifier) =
        extensions.and_then(|extensions| extensions.payment_identifier.as_ref())
    {
        if let Some(required) = identifier.info.required {
            shape.insert(
                "paymentIdentifierRequired".to_string(),
                Value::Bool(required),
            );
        }
        if let Some(id) = &identifier.info.id {
            shape.insert("paymentIdentifierId".to_string(), Value::String(id.clone()));
        }
    }
    Value::Object(shape)
}

fn check_server_field(
    actual: &str,
    expected: Option<&str>,
    field: &str,
) -> Result<(), RunnerError> {
    if expected.is_some_and(|expected| actual != expected) {
        return Err(RunnerError::rejected(format!(
            "{field} does not match the server route"
        )));
    }
    Ok(())
}

fn offer_string<'a>(offer: &'a Value, key: &str) -> Result<&'a str, RunnerError> {
    offer
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| RunnerError::rejected(format!("x402Offer is missing {key}")))
}

fn v1_network(network: &str) -> String {
    if caip2_network_for_cluster(network) == SOLANA_DEVNET {
        "solana-devnet".to_string()
    } else {
        "solana".to_string()
    }
}

fn valid_payment_identifier(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
