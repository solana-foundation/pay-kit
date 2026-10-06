//! Payment Auth transport for JSON-RPC 2.0 and MCP.
//!
//! This module maps pay-kit's transport-neutral MPP challenge, credential,
//! and receipt types to `draft-payment-transport-mcp-00`:
//!
//! - payment challenges use JSON-RPC error `-32042`;
//! - credentials use `_meta["org.paymentauth/credential"]`;
//! - receipts use `_meta["org.paymentauth/receipt"]`.
//!
//! The wire format is intentionally separate from x402's MCP transport,
//! which uses `x402/payment` metadata and MCP tool-error results.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::mpp::{
    Base64UrlJson, ChallengeEcho, Error, IntentName, MethodName, PaymentChallenge,
    PaymentCredential, Receipt,
};

#[cfg(feature = "server")]
use crate::mpp::{server::Mpp, ChargeRequest};

/// JSON-RPC error code for a payment challenge.
pub const PAYMENT_REQUIRED_CODE: i64 = -32042;
/// JSON-RPC error code for a failed payment verification.
pub const PAYMENT_VERIFICATION_FAILED_CODE: i64 = -32043;
/// JSON-RPC error code for a malformed payment credential.
pub const INVALID_PARAMS_CODE: i64 = -32602;
/// JSON-RPC error code for an internal payment processor failure.
pub const INTERNAL_ERROR_CODE: i64 = -32603;

/// MCP metadata key carrying a payment credential.
pub const CREDENTIAL_META_KEY: &str = "org.paymentauth/credential";
/// MCP metadata key carrying a payment receipt.
pub const RECEIPT_META_KEY: &str = "org.paymentauth/receipt";

/// A JSON-RPC request with optional root-level metadata.
///
/// MCP places `_meta` inside `params`; generic JSON-RPC places it at the
/// request root. Servers must accept both placements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    #[serde(default = "jsonrpc_version")]
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Map<String, Value>>,
}

impl Request {
    /// Returns whether this request is a JSON-RPC notification.
    ///
    /// Payment-gated notifications must not be processed because no challenge
    /// can be returned to the caller.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Extract a credential from nested MCP or root JSON-RPC metadata.
    ///
    /// If both placements are present they must be identical. Rejecting
    /// conflicting values avoids intermediaries selecting a different proof
    /// than the application inspected.
    pub fn credential(&self) -> Result<Option<PaymentCredential>, Error> {
        let nested = self
            .params
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|params| params.get("_meta"))
            .and_then(Value::as_object)
            .and_then(|meta| meta.get(CREDENTIAL_META_KEY));
        let root = self
            .meta
            .as_ref()
            .and_then(|meta| meta.get(CREDENTIAL_META_KEY));

        let value = match (nested, root) {
            (None, None) => return Ok(None),
            (Some(value), None) | (None, Some(value)) => value,
            (Some(nested), Some(root)) if nested == root => nested,
            (Some(_), Some(_)) => {
                return Err(Error::Other(
                    "conflicting payment credentials in root and params metadata".into(),
                ))
            }
        };

        let credential: Credential = serde_json::from_value(value.clone())
            .map_err(|error| Error::Other(format!("invalid MCP payment credential: {error}")))?;
        credential.try_into().map(Some)
    }

    /// Attach a credential using MCP's nested `params._meta` placement.
    pub fn set_credential(&mut self, credential: &PaymentCredential) -> Result<(), Error> {
        let credential = Credential::try_from(credential)?;
        let value = serde_json::to_value(credential)
            .map_err(|error| Error::Other(format!("failed to encode MCP credential: {error}")))?;
        let params = self.params.get_or_insert_with(|| Value::Object(Map::new()));
        let params = params.as_object_mut().ok_or_else(|| {
            Error::Other("MCP request params must be an object to carry payment metadata".into())
        })?;
        let meta = params
            .entry("_meta")
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or_else(|| Error::Other("MCP request params._meta must be an object".into()))?;
        meta.insert(CREDENTIAL_META_KEY.into(), value);
        Ok(())
    }

    /// Stable digest binding a challenge to this operation.
    ///
    /// JSON-RPC envelope fields, payment credentials, and transport correlation
    /// metadata are excluded, so a retry may use a new request ID, progress
    /// token, and credential. The method, arguments, and application metadata
    /// remain bound.
    pub fn operation_digest(&self) -> Result<String, Error> {
        let mut params = self.params.clone();
        if let Some(object) = params.as_mut().and_then(Value::as_object_mut) {
            remove_retry_metadata(object);
            if object.is_empty() {
                params = None;
            }
        }
        let operation = serde_json::json!({
            "method": self.method,
            "params": params,
        });
        let canonical = serde_json_canonicalizer::to_vec(&operation).map_err(|error| {
            Error::Other(format!("failed to canonicalize MCP operation: {error}"))
        })?;
        Ok(format!(
            "sha-256:{}",
            crate::mpp::base64url_encode(&Sha256::digest(canonical))
        ))
    }
}

/// Native-JSON payment challenge used by JSON-RPC and MCP.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub id: String,
    pub realm: String,
    pub method: MethodName,
    pub intent: IntentName,
    pub request: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opaque: Option<Value>,
}

impl TryFrom<&PaymentChallenge> for Challenge {
    type Error = Error;

    fn try_from(challenge: &PaymentChallenge) -> Result<Self, Self::Error> {
        if challenge.id.is_empty() {
            return Err(Error::Other(
                "MCP payment challenge id must not be empty".into(),
            ));
        }
        Ok(Self {
            id: challenge.id.clone(),
            realm: challenge.realm.clone(),
            method: challenge.method.clone(),
            intent: challenge.intent.clone(),
            request: challenge.request.decode_value()?,
            expires: challenge.expires.clone(),
            description: challenge.description.clone(),
            digest: challenge.digest.clone(),
            opaque: challenge
                .opaque
                .as_ref()
                .map(Base64UrlJson::decode_value)
                .transpose()?,
        })
    }
}

impl TryFrom<Challenge> for PaymentChallenge {
    type Error = Error;

    fn try_from(challenge: Challenge) -> Result<Self, Self::Error> {
        if challenge.id.is_empty() {
            return Err(Error::Other(
                "MCP payment challenge id must not be empty".into(),
            ));
        }
        Ok(Self {
            id: challenge.id,
            realm: challenge.realm,
            method: challenge.method,
            intent: challenge.intent,
            request: Base64UrlJson::from_value(&challenge.request)?,
            expires: challenge.expires,
            description: challenge.description,
            digest: challenge.digest,
            opaque: challenge
                .opaque
                .as_ref()
                .map(Base64UrlJson::from_value)
                .transpose()?,
        })
    }
}

/// Payment credential carried in MCP request metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub challenge: Challenge,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub payload: Value,
}

impl TryFrom<&PaymentCredential> for Credential {
    type Error = Error;

    fn try_from(credential: &PaymentCredential) -> Result<Self, Self::Error> {
        let challenge = PaymentChallenge {
            id: credential.challenge.id.clone(),
            realm: credential.challenge.realm.clone(),
            method: credential.challenge.method.clone(),
            intent: credential.challenge.intent.clone(),
            request: credential.challenge.request.clone(),
            expires: credential.challenge.expires.clone(),
            description: credential.challenge.description.clone(),
            digest: credential.challenge.digest.clone(),
            opaque: credential.challenge.opaque.clone(),
        };
        Ok(Self {
            challenge: Challenge::try_from(&challenge)?,
            source: credential.source.clone(),
            payload: credential.payload.clone(),
        })
    }
}

impl TryFrom<Credential> for PaymentCredential {
    type Error = Error;

    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        let challenge: PaymentChallenge = credential.challenge.try_into()?;
        Ok(Self {
            challenge: ChallengeEcho {
                id: challenge.id,
                realm: challenge.realm,
                method: challenge.method,
                intent: challenge.intent,
                request: challenge.request,
                expires: challenge.expires,
                description: challenge.description,
                digest: challenge.digest,
                opaque: challenge.opaque,
            },
            source: credential.source,
            payload: credential.payload,
        })
    }
}

/// Payment receipt carried in MCP response metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpReceipt {
    pub status: crate::mpp::ReceiptStatus,
    pub method: MethodName,
    pub timestamp: String,
    pub challenge_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl From<&Receipt> for McpReceipt {
    fn from(receipt: &Receipt) -> Self {
        Self {
            status: receipt.status.clone(),
            method: receipt.method.clone(),
            timestamp: receipt.timestamp.clone(),
            challenge_id: receipt.challenge_id.clone(),
            reference: (!receipt.reference.is_empty()).then(|| receipt.reference.clone()),
        }
    }
}

/// JSON-RPC payment error response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub jsonrpc: String,
    pub id: Value,
    pub error: ErrorObject,
}

/// JSON-RPC error object used for payment failures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorObject {
    pub code: i64,
    pub message: String,
    pub data: ErrorData,
}

/// Structured payment data in a JSON-RPC error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorData {
    #[serde(default = "payment_required_status")]
    pub http_status: u16,
    pub challenges: Vec<Challenge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<Failure>,
}

/// Optional machine- and human-readable verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Result of applying a Solana charge gate to an MCP request.
#[cfg(feature = "server")]
#[derive(Debug, Clone)]
pub enum ChargeGateResult {
    /// The tool may execute. Attach `receipt` to its result with
    /// [`attach_receipt`] before returning it.
    Paid { receipt: Receipt },
    /// Return this JSON-RPC payment response without executing the tool.
    Payment(ErrorResponse),
}

#[cfg(feature = "server")]
impl Mpp {
    /// Gate one MCP operation with a Solana charge priced in display units.
    ///
    /// The challenge is cryptographically bound to the MCP method and params
    /// (excluding request ID and payment metadata), which prevents replaying a
    /// credential issued for one tool or argument set against another.
    /// Notifications are rejected because JSON-RPC cannot return their payment
    /// challenge.
    pub async fn gate_mcp_charge(
        &self,
        request: &Request,
        amount: &str,
    ) -> Result<ChargeGateResult, Error> {
        let id = request.id.clone().ok_or_else(|| {
            Error::Other("payment-gated MCP operations must include a JSON-RPC id".into())
        })?;
        let challenge = bind_operation(
            self.charge(amount)?,
            request,
            &self.challenge_binding_secret,
        )?;
        let wire_challenge = Challenge::try_from(&challenge)?;

        let credential = match request.credential() {
            Ok(Some(credential)) => credential,
            Ok(None) => {
                return Ok(ChargeGateResult::Payment(ErrorResponse::payment_required(
                    id,
                    vec![wire_challenge],
                )))
            }
            Err(error) => {
                return Err(Error::Other(format!(
                    "malformed MCP payment credential: {error}"
                )))
            }
        };

        let operation_digest = request.operation_digest()?;
        let credential_digest = credential.challenge.digest.as_deref().unwrap_or_default();
        if !crate::mpp::protocol::core::challenge::constant_time_eq(
            credential_digest,
            &operation_digest,
        ) {
            return Ok(ChargeGateResult::Payment(
                ErrorResponse::verification_failed(
                    id,
                    vec![wire_challenge],
                    Failure {
                        reason: Some("operation-mismatch".into()),
                        detail: Some(
                            "payment credential was issued for a different MCP operation".into(),
                        ),
                    },
                ),
            ));
        }

        let expected: ChargeRequest = challenge.request.decode()?;
        match self
            .verify_credential_with_expected(&credential, &expected)
            .await
        {
            Ok(receipt) => Ok(ChargeGateResult::Paid { receipt }),
            Err(error) => Ok(ChargeGateResult::Payment(
                ErrorResponse::verification_failed(
                    id,
                    vec![wire_challenge],
                    Failure {
                        reason: error.code.map(str::to_owned),
                        detail: Some(error.message),
                    },
                ),
            )),
        }
    }
}

impl ErrorResponse {
    /// Construct a `-32042 Payment Required` response.
    pub fn payment_required(id: Value, challenges: Vec<Challenge>) -> Self {
        Self::new(
            id,
            PAYMENT_REQUIRED_CODE,
            "Payment Required",
            challenges,
            None,
        )
    }

    /// Construct a `-32043 Payment Verification Failed` response.
    pub fn verification_failed(id: Value, challenges: Vec<Challenge>, failure: Failure) -> Self {
        Self::new(
            id,
            PAYMENT_VERIFICATION_FAILED_CODE,
            "Payment Verification Failed",
            challenges,
            Some(failure),
        )
    }

    fn new(
        id: Value,
        code: i64,
        message: &str,
        challenges: Vec<Challenge>,
        failure: Option<Failure>,
    ) -> Self {
        Self {
            jsonrpc: jsonrpc_version(),
            id,
            error: ErrorObject {
                code,
                message: message.into(),
                data: ErrorData {
                    http_status: payment_required_status(),
                    challenges,
                    problem: None,
                    failure,
                },
            },
        }
    }
}

/// Add a payment receipt to an MCP result object.
pub fn attach_receipt(result: &mut Value, receipt: &Receipt) -> Result<(), Error> {
    if receipt.challenge_id.is_empty() {
        return Err(Error::Other(
            "MCP payment receipts require a challengeId".into(),
        ));
    }
    let result = result
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP result must be an object to carry a receipt".into()))?;
    let meta = result
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP result._meta must be an object".into()))?;
    let receipt = serde_json::to_value(McpReceipt::from(receipt))
        .map_err(|error| Error::Other(format!("failed to encode MCP receipt: {error}")))?;
    meta.insert(RECEIPT_META_KEY.into(), receipt);
    Ok(())
}

/// Extract a payment receipt from an MCP result object.
pub fn receipt(result: &Value) -> Result<Option<McpReceipt>, Error> {
    let Some(value) = result
        .as_object()
        .and_then(|result| result.get("_meta"))
        .and_then(Value::as_object)
        .and_then(|meta| meta.get(RECEIPT_META_KEY))
    else {
        return Ok(None);
    };
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|error| Error::Other(format!("invalid MCP payment receipt: {error}")))
}

/// Payment methods advertised in MCP's experimental capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub methods: BTreeMap<String, MethodCapabilities>,
}

/// Intents supported by one payment method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodCapabilities {
    pub intents: Vec<String>,
}

impl Capabilities {
    /// Advertise the Solana intents supported by this pay-kit server.
    pub fn solana(intents: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            methods: BTreeMap::from([(
                "solana".into(),
                MethodCapabilities {
                    intents: intents.into_iter().map(Into::into).collect(),
                },
            )]),
        }
    }
}

/// Merge payment support into an MCP initialize capability object.
pub fn advertise(capabilities: &mut Value, payment: Capabilities) -> Result<(), Error> {
    let capabilities = capabilities
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP initialize capabilities must be a JSON object".into()))?;
    let experimental = capabilities
        .entry("experimental")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP capabilities.experimental must be an object".into()))?;
    experimental.insert(
        "payment".into(),
        serde_json::to_value(payment).map_err(|error| {
            Error::Other(format!(
                "failed to encode MCP payment capabilities: {error}"
            ))
        })?,
    );
    Ok(())
}

fn jsonrpc_version() -> String {
    "2.0".into()
}

fn payment_required_status() -> u16 {
    402
}

#[cfg(feature = "server")]
fn bind_operation(
    challenge: PaymentChallenge,
    request: &Request,
    challenge_binding_secret: &str,
) -> Result<PaymentChallenge, Error> {
    let digest = request.operation_digest()?;
    let PaymentChallenge {
        realm,
        method,
        intent,
        request,
        expires,
        description,
        opaque,
        ..
    } = challenge;
    Ok(PaymentChallenge::with_challenge_binding_secret_full(
        challenge_binding_secret,
        realm,
        method,
        intent,
        request,
        expires.as_deref(),
        Some(&digest),
        description.as_deref(),
        opaque,
    ))
}

fn remove_retry_metadata(params: &mut Map<String, Value>) {
    let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) else {
        return;
    };
    meta.remove(CREDENTIAL_META_KEY);
    meta.remove("progressToken");
    if meta.is_empty() {
        params.remove("_meta");
    }
}

/// Adapters for the official [`rmcp`](https://crates.io/crates/rmcp) SDK.
#[cfg(feature = "rmcp")]
pub mod rmcp {
    use super::{
        attach_receipt as attach_json_receipt, receipt as json_receipt, Capabilities,
        ChargeGateResult, Credential, ErrorResponse, McpReceipt, Request, CREDENTIAL_META_KEY,
        RECEIPT_META_KEY,
    };
    use crate::mpp::{server::Mpp, Error, PaymentCredential, Receipt};
    use ::rmcp::{
        model::{
            CallToolRequestParams, CallToolResult, ErrorCode, ExperimentalCapabilities, MetaObject,
            RequestMetaObject, ServerCapabilities,
        },
        ErrorData,
    };
    use serde_json::Value;

    /// Gate an rmcp `tools/call` with a Solana charge.
    ///
    /// Pass `context.meta` from rmcp's `RequestContext`: rmcp moves wire-level
    /// `params._meta` there before dispatching the tool handler. On success,
    /// attach the returned receipt with [`attach_receipt`]. On challenge or
    /// verification failure, the returned `ErrorData` carries the required
    /// `-32042` or `-32043` JSON-RPC response.
    pub async fn gate_charge(
        payment: &Mpp,
        params: &CallToolRequestParams,
        meta: &RequestMetaObject,
        amount: &str,
    ) -> Result<Receipt, ErrorData> {
        let request = request(params, meta).map_err(internal_error)?;
        if let Err(error) = request.credential() {
            return Err(ErrorData::new(
                ErrorCode::INVALID_PARAMS,
                "Malformed payment credential",
                Some(serde_json::json!({ "detail": error.to_string() })),
            ));
        }
        match payment
            .gate_mcp_charge(&request, amount)
            .await
            .map_err(internal_error)?
        {
            ChargeGateResult::Paid { receipt } => Ok(receipt),
            ChargeGateResult::Payment(response) => Err(error_data(response)),
        }
    }

    /// Insert a Solana payment credential into an outgoing rmcp tool call.
    pub fn set_credential(
        params: &mut CallToolRequestParams,
        credential: &PaymentCredential,
    ) -> Result<(), Error> {
        let credential = Credential::try_from(credential)?;
        let value = serde_json::to_value(credential)
            .map_err(|error| Error::Other(format!("failed to encode rmcp credential: {error}")))?;
        let meta = params.meta.get_or_insert_with(RequestMetaObject::new);
        meta.insert(CREDENTIAL_META_KEY.into(), value);
        Ok(())
    }

    /// Attach a successful Solana payment receipt to an rmcp tool result.
    pub fn attach_receipt(result: &mut CallToolResult, receipt: &Receipt) -> Result<(), Error> {
        let mut value = serde_json::to_value(&*result)
            .map_err(|error| Error::Other(format!("failed to encode rmcp result: {error}")))?;
        attach_json_receipt(&mut value, receipt)?;
        let receipt = value
            .get("_meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get(RECEIPT_META_KEY))
            .cloned()
            .ok_or_else(|| Error::Other("rmcp receipt metadata was not created".into()))?;
        result
            .meta
            .get_or_insert_with(MetaObject::new)
            .insert(RECEIPT_META_KEY.into(), receipt);
        Ok(())
    }

    /// Extract a Payment Auth receipt from an rmcp tool result.
    pub fn receipt(result: &CallToolResult) -> Result<Option<McpReceipt>, Error> {
        let value = serde_json::to_value(result)
            .map_err(|error| Error::Other(format!("failed to encode rmcp result: {error}")))?;
        json_receipt(&value)
    }

    /// Extract transport-neutral Solana payment challenges from an rmcp error.
    ///
    /// Returns `Ok(None)` for errors unrelated to payment. Clients can select a
    /// challenge, build the existing pay-kit charge/session credential, attach
    /// it with [`set_credential`], and retry the same tool call.
    pub fn challenges(
        error: &ErrorData,
    ) -> Result<Option<Vec<crate::mpp::PaymentChallenge>>, Error> {
        if error.code.0 != super::PAYMENT_REQUIRED_CODE as i32
            && error.code.0 != super::PAYMENT_VERIFICATION_FAILED_CODE as i32
        {
            return Ok(None);
        }
        let data: super::ErrorData =
            serde_json::from_value(error.data.clone().ok_or_else(|| {
                Error::Other("rmcp payment error is missing challenge data".into())
            })?)
            .map_err(|decode| {
                Error::Other(format!("invalid rmcp payment challenge data: {decode}"))
            })?;
        data.challenges
            .into_iter()
            .map(crate::mpp::PaymentChallenge::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    /// Advertise Solana Payment Auth support in rmcp server capabilities.
    pub fn advertise(
        capabilities: &mut ServerCapabilities,
        payment: Capabilities,
    ) -> Result<(), Error> {
        let payment = serde_json::to_value(payment)
            .map_err(|error| Error::Other(format!("failed to encode rmcp capabilities: {error}")))?
            .as_object()
            .cloned()
            .ok_or_else(|| Error::Other("payment capabilities must encode as an object".into()))?;
        capabilities
            .experimental
            .get_or_insert_with(ExperimentalCapabilities::new)
            .insert("payment".into(), payment);
        Ok(())
    }

    /// Convert rmcp tool-call params and dispatch metadata to the core transport
    /// request. Useful for Solana session handlers that manage their own
    /// channel lifecycle.
    pub fn request(
        params: &CallToolRequestParams,
        meta: &RequestMetaObject,
    ) -> Result<Request, Error> {
        let mut params = serde_json::to_value(params)
            .map_err(|error| Error::Other(format!("failed to encode rmcp tool call: {error}")))?;
        let params_object = params
            .as_object_mut()
            .ok_or_else(|| Error::Other("rmcp tool-call params must encode as an object".into()))?;
        params_object.insert(
            "_meta".into(),
            serde_json::to_value(meta).map_err(|error| {
                Error::Other(format!("failed to encode rmcp metadata: {error}"))
            })?,
        );
        Ok(Request {
            jsonrpc: "2.0".into(),
            // rmcp owns the actual JSON-RPC ID and wraps ErrorData with it.
            id: Some(Value::Null),
            method: "tools/call".into(),
            params: Some(params),
            meta: None,
        })
    }

    /// Convert a core payment challenge/failure into the protocol error rmcp
    /// expects from a tool handler.
    pub fn error_data(response: ErrorResponse) -> ErrorData {
        ErrorData::new(
            ErrorCode(response.error.code as i32),
            response.error.message,
            serde_json::to_value(response.error.data).ok(),
        )
    }

    fn internal_error(error: Error) -> ErrorData {
        ErrorData::new(
            ErrorCode::INTERNAL_ERROR,
            "Payment processing failed",
            Some(serde_json::json!({ "detail": error.to_string() })),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::mpp::{Base64UrlJson, PaymentChallenge};
        use ::rmcp::{
            model::{CallToolResponse, ClientConfig, ContentBlock, ServerConfig},
            service::{serve_directly, RequestContext, RoleClient, RoleServer},
            ServerHandler,
        };
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Default)]
        struct RetryState {
            digest: Option<String>,
            progress_tokens: Vec<Value>,
        }

        #[derive(Debug, Clone, Default)]
        struct RetryServer {
            state: Arc<Mutex<RetryState>>,
        }

        impl ServerHandler for RetryServer {
            async fn call_tool(
                &self,
                params: CallToolRequestParams,
                context: RequestContext<RoleServer>,
            ) -> Result<CallToolResponse, ErrorData> {
                let digest = request(&params, &context.meta)
                    .and_then(|request| request.operation_digest())
                    .map_err(internal_error)?;
                let mut state = self.state.lock().map_err(|_| {
                    ErrorData::new(ErrorCode::INTERNAL_ERROR, "retry state poisoned", None)
                })?;
                state.progress_tokens.push(
                    context
                        .meta
                        .get("progressToken")
                        .cloned()
                        .expect("rmcp should attach a progress token"),
                );

                if let Some(expected) = state.digest.as_ref() {
                    if expected != &digest {
                        return Err(ErrorData::new(
                            ErrorCode(super::super::PAYMENT_VERIFICATION_FAILED_CODE as i32),
                            "operation-mismatch",
                            None,
                        ));
                    }
                    Ok(CallToolResult::success(vec![ContentBlock::text("paid")]).into())
                } else {
                    state.digest = Some(digest);
                    Err(ErrorData::new(
                        ErrorCode(super::super::PAYMENT_REQUIRED_CODE as i32),
                        "Payment Required",
                        None,
                    ))
                }
            }
        }

        #[test]
        fn credential_and_receipt_use_rmcp_metadata() {
            let challenge = PaymentChallenge::new(
                "challenge-1",
                "compute.example.com",
                "solana",
                "charge",
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
            );
            let credential = PaymentCredential::new(
                challenge.to_echo(),
                serde_json::json!({"type": "signature", "signature": "sig"}),
            );
            let mut params = CallToolRequestParams::new("compute");
            set_credential(&mut params, &credential).unwrap();
            assert!(params
                .meta
                .as_ref()
                .unwrap()
                .contains_key(CREDENTIAL_META_KEY));

            let mut result = CallToolResult::success(Vec::new());
            let paid = Receipt::success("solana", "tx", "challenge-1");
            attach_receipt(&mut result, &paid).unwrap();
            assert_eq!(
                receipt(&result).unwrap().unwrap().challenge_id,
                "challenge-1"
            );
        }

        #[test]
        fn advertises_rmcp_payment_capability() {
            let mut capabilities = ServerCapabilities::default();
            advertise(
                &mut capabilities,
                Capabilities::solana(["charge", "session"]),
            )
            .unwrap();
            assert!(capabilities.experimental.unwrap().contains_key("payment"));
        }

        #[test]
        fn extracts_payment_challenges_from_rmcp_errors() {
            let challenge = super::super::Challenge::try_from(&PaymentChallenge::new(
                "challenge-1",
                "compute.example.com",
                "solana",
                "session",
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
            ))
            .unwrap();
            let error = error_data(ErrorResponse::payment_required(
                Value::Null,
                vec![challenge],
            ));
            let challenges = challenges(&error).unwrap().unwrap();
            assert_eq!(challenges[0].intent.as_str(), "session");
        }

        #[test]
        fn extracts_payment_challenges_without_http_status() {
            let challenge = super::super::Challenge::try_from(&PaymentChallenge::new(
                "challenge-1",
                "compute.example.com",
                "solana",
                "charge",
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
            ))
            .unwrap();
            let error = ErrorData::new(
                ErrorCode(super::super::PAYMENT_REQUIRED_CODE as i32),
                "Payment Required",
                Some(serde_json::json!({"challenges": [challenge]})),
            );

            let challenges = challenges(&error).unwrap().unwrap();
            assert_eq!(challenges[0].intent.as_str(), "charge");
        }

        #[tokio::test]
        async fn paid_retry_ignores_rmcp_progress_token() {
            let (server_transport, client_transport) = tokio::io::duplex(4096);
            let server = RetryServer::default();
            let state = Arc::clone(&server.state);
            let running_server = serve_directly::<RoleServer, _, _, _, _>(
                server,
                server_transport,
                Some(ClientConfig::default()),
            );
            let server_task = tokio::spawn(async move { running_server.waiting().await });
            let client = serve_directly::<RoleClient, _, _, _, _>(
                (),
                client_transport,
                Some(ServerConfig::default().into()),
            );

            let mut params =
                CallToolRequestParams::new("compute").with_arguments(serde_json::Map::from_iter([
                    ("cpu".into(), serde_json::json!(1)),
                ]));
            let error = client.call_tool(params.clone()).await.unwrap_err();
            assert!(matches!(
                error,
                ::rmcp::ServiceError::McpError(ref data)
                    if data.code.0 == super::super::PAYMENT_REQUIRED_CODE as i32
            ));

            let payment = PaymentChallenge::new(
                "challenge-1",
                "compute.example.com",
                "solana",
                "charge",
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
            );
            let credential = PaymentCredential::new(
                payment.to_echo(),
                serde_json::json!({"type": "signature", "signature": "sig"}),
            );
            set_credential(&mut params, &credential).unwrap();

            client.call_tool(params).await.unwrap();
            client.cancel().await.unwrap();
            server_task.await.unwrap().unwrap();

            let state = state.lock().unwrap();
            assert_eq!(state.progress_tokens.len(), 2);
            assert_ne!(state.progress_tokens[0], state.progress_tokens[1]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payment_challenge() -> PaymentChallenge {
        PaymentChallenge::new(
            "challenge-1",
            "compute.example.com",
            "solana",
            "session",
            Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "currency": "USDC"
            }))
            .unwrap(),
        )
        .with_expires("2030-01-01T00:00:00Z")
        .with_description("Compute execution")
    }

    #[test]
    fn challenge_uses_native_json_and_round_trips() {
        let payment = payment_challenge();
        let challenge = Challenge::try_from(&payment).unwrap();
        assert_eq!(challenge.request["amount"], "1000");
        assert_eq!(challenge.description.as_deref(), Some("Compute execution"));

        let round_trip = PaymentChallenge::try_from(challenge).unwrap();
        assert_eq!(
            round_trip.request.decode_value().unwrap(),
            payment.request.decode_value().unwrap()
        );
        assert_eq!(round_trip.description, payment.description);
    }

    #[test]
    fn request_reads_nested_and_root_credentials_but_rejects_conflicts() {
        let payment = payment_challenge();
        let credential =
            PaymentCredential::new(payment.to_echo(), serde_json::json!({"proof": "ok"}));
        let mut request = Request {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            params: Some(serde_json::json!({"name": "compute"})),
            meta: None,
        };
        request.set_credential(&credential).unwrap();
        assert_eq!(
            request.credential().unwrap().unwrap().payload["proof"],
            "ok"
        );

        request.meta = Some(Map::from_iter([(
            CREDENTIAL_META_KEY.into(),
            serde_json::json!({"different": true}),
        )]));
        assert!(request.credential().is_err());
    }

    #[test]
    fn operation_digest_ignores_request_id_and_payment_credential() {
        let payment = payment_challenge();
        let credential =
            PaymentCredential::new(payment.to_echo(), serde_json::json!({"proof": "ok"}));
        let mut request = Request {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(1)),
            method: "tools/call".into(),
            params: Some(serde_json::json!({"name": "compute", "arguments": {"cpu": 1}})),
            meta: None,
        };
        let expected = request.operation_digest().unwrap();
        request.id = Some(serde_json::json!(2));
        request.set_credential(&credential).unwrap();
        assert_eq!(request.operation_digest().unwrap(), expected);

        request.params.as_mut().unwrap()["arguments"]["cpu"] = serde_json::json!(2);
        assert_ne!(request.operation_digest().unwrap(), expected);
    }

    #[test]
    fn operation_digest_preserves_requests_without_params_on_paid_retry() {
        let payment = payment_challenge();
        let credential =
            PaymentCredential::new(payment.to_echo(), serde_json::json!({"proof": "ok"}));
        let mut request = Request {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(1)),
            method: "ping".into(),
            params: None,
            meta: None,
        };
        let expected = request.operation_digest().unwrap();

        request.set_credential(&credential).unwrap();

        assert_eq!(request.operation_digest().unwrap(), expected);
        let decoded = request.credential().unwrap().unwrap();
        assert_eq!(decoded.challenge.id, credential.challenge.id);
        assert_eq!(decoded.payload, credential.payload);
    }

    #[test]
    fn error_and_receipt_follow_payment_auth_mcp_shape() {
        let challenge = Challenge::try_from(&payment_challenge()).unwrap();
        let response = ErrorResponse::payment_required(serde_json::json!(7), vec![challenge]);
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["error"]["code"], PAYMENT_REQUIRED_CODE);
        assert_eq!(value["error"]["data"]["httpStatus"], 402);

        let mut result = serde_json::json!({"content": []});
        let receipt_value = Receipt::success("solana", "tx-1", "challenge-1");
        attach_receipt(&mut result, &receipt_value).unwrap();
        assert_eq!(
            receipt(&result).unwrap().unwrap().challenge_id,
            "challenge-1"
        );
    }

    #[test]
    fn advertises_payment_capabilities_without_clobbering_others() {
        let mut capabilities = serde_json::json!({"tools": {}});
        advertise(
            &mut capabilities,
            Capabilities::solana(["charge", "session"]),
        )
        .unwrap();
        assert!(capabilities.get("tools").is_some());
        assert_eq!(
            capabilities["experimental"]["payment"]["methods"]["solana"]["intents"][1],
            "session"
        );
    }
}
