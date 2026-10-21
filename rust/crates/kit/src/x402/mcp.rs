//! x402 transport helpers for Model Context Protocol tool calls.
//!
//! x402 uses tool results for payment challenges, unlike Payment Auth/MPP,
//! which uses JSON-RPC errors. Keeping these codecs in separate modules makes
//! it difficult for an integration to accidentally emit one protocol's wire
//! format while processing the other.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::x402::{exact::PaymentRequiredEnvelope, Error};

#[cfg(feature = "server")]
use crate::x402::server::{ExactOptions, VerifiedExactPayment, X402};

/// MCP request metadata key carrying an x402 payment payload.
pub const PAYMENT_META_KEY: &str = "x402/payment";
/// MCP result metadata key carrying an x402 settlement response.
pub const PAYMENT_RESPONSE_META_KEY: &str = "x402/payment-response";

/// Canonical x402 settlement metadata returned after a paid tool succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementResponse {
    pub success: bool,
    pub transaction: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
}

impl SettlementResponse {
    /// Construct successful settlement metadata.
    pub fn success(transaction: impl Into<String>, network: impl Into<String>) -> Self {
        Self {
            success: true,
            transaction: transaction.into(),
            network: network.into(),
            payer: None,
            error_reason: None,
        }
    }

    /// Add the payer address when it is available to the settlement layer.
    pub fn with_payer(mut self, payer: impl Into<String>) -> Self {
        self.payer = Some(payer.into());
        self
    }
}

/// Result of applying an x402 exact gate to an MCP tool call.
#[cfg(feature = "server")]
#[derive(Debug)]
pub enum ExactGateResult {
    /// Payment verified. The caller must settle it before executing the tool.
    Verified(VerifiedExactPayment),
    /// Return this MCP tool-error result without executing the tool.
    PaymentRequired(Value),
}

/// Read a scheme-neutral x402 payment from MCP request metadata.
pub fn payment(params: &Value) -> Result<Option<Value>, Error> {
    let params = params
        .as_object()
        .ok_or_else(|| Error::Other("MCP request params must be an object".into()))?;
    let Some(meta) = params.get("_meta") else {
        return Ok(None);
    };
    let meta = meta
        .as_object()
        .ok_or_else(|| Error::Other("MCP request params._meta must be an object".into()))?;
    let Some(value) = meta.get(PAYMENT_META_KEY) else {
        return Ok(None);
    };

    if !value.is_object() {
        return Err(Error::Other(
            "MCP x402 payment metadata must be an object".into(),
        ));
    }
    Ok(Some(value.clone()))
}

/// Insert any serializable x402 scheme payload in MCP request metadata.
pub fn set_payment<T: Serialize + ?Sized>(params: &mut Value, payment: &T) -> Result<(), Error> {
    let params = params
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP request params must be an object".into()))?;
    let meta = params
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP request params._meta must be an object".into()))?;
    meta.insert(
        PAYMENT_META_KEY.into(),
        serde_json::to_value(payment)
            .map_err(|error| Error::Other(format!("failed to encode MCP x402 payment: {error}")))?,
    );
    Ok(())
}

/// Decode a normal HTTP payment-header value for use in MCP metadata.
pub fn payment_from_header(header: &str) -> Result<Value, Error> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header)
        .map_err(|error| Error::Other(format!("invalid base64 x402 payment: {error}")))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| Error::Other(format!("invalid x402 payment payload: {error}")))?;
    if !value.is_object() {
        return Err(Error::Other(
            "x402 payment payload must be an object".into(),
        ));
    }
    Ok(value)
}

/// Build the dual-format tool-error result required by the x402 MCP spec.
pub fn payment_required(requirements: &PaymentRequiredEnvelope) -> Result<Value, Error> {
    let structured = serde_json::to_value(requirements)
        .map_err(|error| Error::Other(format!("failed to encode x402 requirements: {error}")))?;
    Ok(serde_json::json!({
        "content": [{ "type": "text", "text": serde_json::to_string(&structured)
            .map_err(|error| Error::Other(format!("failed to encode x402 requirements: {error}")))? }],
        "structuredContent": structured,
        "isError": true
    }))
}

/// Extract x402 requirements, preferring `structuredContent` and falling back
/// to the JSON string in the first text content block as required by the spec.
pub fn requirements(result: &Value) -> Result<Option<PaymentRequiredEnvelope>, Error> {
    let Some(result) = result.as_object() else {
        return Err(Error::Other("MCP tool result must be an object".into()));
    };

    if let Some(value) = result.get("structuredContent") {
        if looks_like_requirements(value) {
            return decode_requirements(value.clone()).map(Some);
        }
    }

    let Some(text) = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| content.first())
        .and_then(Value::as_object)
        .filter(|content| content.get("type").and_then(Value::as_str) == Some("text"))
        .and_then(|content| content.get("text"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Ok(None);
    };
    if !looks_like_requirements(&value) {
        return Ok(None);
    }
    decode_requirements(value).map(Some)
}

/// Attach canonical settlement metadata to an MCP tool result.
pub fn attach_payment_response(
    result: &mut Value,
    response: &(impl Serialize + ?Sized),
) -> Result<(), Error> {
    let result = result
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP tool result must be an object".into()))?;
    let meta = result
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| Error::Other("MCP tool result._meta must be an object".into()))?;
    meta.insert(
        PAYMENT_RESPONSE_META_KEY.into(),
        serde_json::to_value(response).map_err(|error| {
            Error::Other(format!("failed to encode MCP x402 settlement: {error}"))
        })?,
    );
    Ok(())
}

/// Extract scheme-neutral settlement metadata from an MCP tool result.
pub fn payment_response(result: &Value) -> Result<Option<Value>, Error> {
    let Some(value) = result
        .as_object()
        .and_then(|result| result.get("_meta"))
        .and_then(Value::as_object)
        .and_then(|meta| meta.get(PAYMENT_RESPONSE_META_KEY))
    else {
        return Ok(None);
    };
    if !value.is_object() {
        return Err(Error::Other(
            "MCP x402 settlement response must be an object".into(),
        ));
    }
    Ok(Some(value.clone()))
}

#[cfg(feature = "server")]
impl X402 {
    /// Verify an x402 exact payment carried by MCP params.
    ///
    /// Missing, malformed, and invalid payments return a spec-shaped tool
    /// error. A verified payment must still be settled before the tool runs;
    /// attach the resulting [`SettlementResponse`] to the successful result.
    pub async fn gate_mcp_exact(
        &self,
        params: &Value,
        amount: &str,
        options: ExactOptions<'_>,
    ) -> Result<ExactGateResult, Error> {
        let mut challenge = self.exact_with_options(amount, options.clone())?;
        let payment = match payment(params) {
            Ok(Some(payment)) => payment,
            Ok(None) => {
                return Ok(ExactGateResult::PaymentRequired(payment_required(
                    &challenge,
                )?))
            }
            Err(error) => {
                challenge.error = Some(error.to_string());
                return Ok(ExactGateResult::PaymentRequired(payment_required(
                    &challenge,
                )?));
            }
        };

        let payment: crate::x402::exact::PaymentSignatureEnvelope =
            match serde_json::from_value(payment) {
                Ok(payment) => payment,
                Err(error) => {
                    challenge.error = Some(format!("invalid x402 exact payment: {error}"));
                    return Ok(ExactGateResult::PaymentRequired(payment_required(
                        &challenge,
                    )?));
                }
            };
        let json = serde_json::to_vec(&payment)
            .map_err(|error| Error::Other(format!("failed to encode MCP x402 payment: {error}")))?;
        let header = base64::engine::general_purpose::STANDARD.encode(json);
        match self.process_payment(&header, amount, options).await {
            Ok(verified) => Ok(ExactGateResult::Verified(verified)),
            Err(error) => {
                challenge.error = Some(error.to_string());
                Ok(ExactGateResult::PaymentRequired(payment_required(
                    &challenge,
                )?))
            }
        }
    }
}

fn looks_like_requirements(value: &Value) -> bool {
    value.get("x402Version").is_some() && value.get("accepts").and_then(Value::as_array).is_some()
}

fn decode_requirements(value: Value) -> Result<PaymentRequiredEnvelope, Error> {
    serde_json::from_value::<PaymentRequiredEnvelope>(value)
        .map(PaymentRequiredEnvelope::with_resource_on_accepts)
        .map_err(|error| Error::Other(format!("invalid MCP x402 requirements: {error}")))
}

/// Adapters for the official [`rmcp`](https://crates.io/crates/rmcp) SDK.
#[cfg(feature = "rmcp")]
pub mod rmcp {
    use super::{
        payment_from_header, payment_response as json_payment_response,
        requirements as json_requirements, ExactGateResult as JsonExactGateResult,
        PAYMENT_META_KEY, PAYMENT_RESPONSE_META_KEY,
    };
    use crate::x402::{
        exact::PaymentRequiredEnvelope,
        server::{ExactOptions, VerifiedExactPayment, X402},
        Error,
    };
    use ::rmcp::model::{CallToolRequestParams, CallToolResult, MetaObject, RequestMetaObject};
    use serde::Serialize;
    use serde_json::Value;

    /// Result of applying an x402 exact gate to an rmcp tool call.
    #[derive(Debug)]
    pub enum ExactGateResult {
        /// Payment verified. Settle it before executing the tool.
        Verified(VerifiedExactPayment),
        /// Return this tool-error result without executing the tool.
        PaymentRequired(CallToolResult),
    }

    /// Verify an x402 exact payment from rmcp request metadata.
    pub async fn gate_exact(
        payment: &X402,
        params: &CallToolRequestParams,
        meta: &RequestMetaObject,
        amount: &str,
        options: ExactOptions<'_>,
    ) -> Result<ExactGateResult, Error> {
        let mut value = serde_json::to_value(params)
            .map_err(|error| Error::Other(format!("failed to encode rmcp tool call: {error}")))?;
        let params = value
            .as_object_mut()
            .ok_or_else(|| Error::Other("rmcp tool-call params must encode as an object".into()))?;
        params.insert(
            "_meta".into(),
            serde_json::to_value(meta).map_err(|error| {
                Error::Other(format!("failed to encode rmcp metadata: {error}"))
            })?,
        );

        match payment.gate_mcp_exact(&value, amount, options).await? {
            JsonExactGateResult::Verified(verified) => Ok(ExactGateResult::Verified(verified)),
            JsonExactGateResult::PaymentRequired(result) => {
                let result = serde_json::from_value(result).map_err(|error| {
                    Error::Other(format!("failed to decode rmcp x402 tool result: {error}"))
                })?;
                Ok(ExactGateResult::PaymentRequired(result))
            }
        }
    }

    /// Insert an x402 payment into an outgoing rmcp tool call.
    pub fn set_payment<T: Serialize + ?Sized>(
        params: &mut CallToolRequestParams,
        payment: &T,
    ) -> Result<(), Error> {
        let value = serde_json::to_value(payment).map_err(|error| {
            Error::Other(format!("failed to encode rmcp x402 payment: {error}"))
        })?;
        params
            .meta
            .get_or_insert_with(RequestMetaObject::new)
            .insert(PAYMENT_META_KEY.into(), value);
        Ok(())
    }

    /// Decode an HTTP-style payment header and insert it into an rmcp call.
    pub fn set_payment_header(
        params: &mut CallToolRequestParams,
        header: &str,
    ) -> Result<(), Error> {
        set_payment(params, &payment_from_header(header)?)
    }

    /// Extract an x402 payment from rmcp request metadata.
    pub fn payment(meta: &RequestMetaObject) -> Result<Option<Value>, Error> {
        let Some(value) = meta.get(PAYMENT_META_KEY) else {
            return Ok(None);
        };
        if !value.is_object() {
            return Err(Error::Other(
                "rmcp x402 payment metadata must be an object".into(),
            ));
        }
        Ok(Some(value.clone()))
    }

    /// Build the dual-format rmcp tool error required for an x402 challenge.
    pub fn payment_required(
        requirements: &PaymentRequiredEnvelope,
    ) -> Result<CallToolResult, Error> {
        let value = serde_json::to_value(requirements).map_err(|error| {
            Error::Other(format!("failed to encode x402 requirements: {error}"))
        })?;
        Ok(CallToolResult::structured_error(value))
    }

    /// Extract x402 requirements from either rmcp result representation.
    pub fn requirements(result: &CallToolResult) -> Result<Option<PaymentRequiredEnvelope>, Error> {
        let value = serde_json::to_value(result)
            .map_err(|error| Error::Other(format!("failed to encode rmcp result: {error}")))?;
        json_requirements(&value)
    }

    /// Attach x402 settlement metadata to a successful rmcp tool result.
    pub fn attach_payment_response<T: Serialize + ?Sized>(
        result: &mut CallToolResult,
        response: &T,
    ) -> Result<(), Error> {
        let value = serde_json::to_value(response).map_err(|error| {
            Error::Other(format!("failed to encode rmcp x402 settlement: {error}"))
        })?;
        result
            .meta
            .get_or_insert_with(MetaObject::new)
            .insert(PAYMENT_RESPONSE_META_KEY.into(), value);
        Ok(())
    }

    /// Extract x402 settlement metadata from an rmcp tool result.
    pub fn payment_response(result: &CallToolResult) -> Result<Option<Value>, Error> {
        let value = serde_json::to_value(result)
            .map_err(|error| Error::Other(format!("failed to encode rmcp result: {error}")))?;
        json_payment_response(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::{
        exact::{PaymentProof, PaymentSignatureEnvelope, ResourceInfo},
        X402_VERSION_V1, X402_VERSION_V2,
    };

    fn challenge() -> PaymentRequiredEnvelope {
        serde_json::from_value(serde_json::json!({
            "x402Version": 2,
            "error": "Payment required",
            "resource": { "url": "mcp://tool/weather" },
            "accepts": [{
                "scheme": "exact",
                "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                "amount": "1000",
                "asset": "USDC",
                "payTo": "11111111111111111111111111111111",
                "maxTimeoutSeconds": 60,
                "extra": {}
            }]
        }))
        .unwrap()
    }

    fn payment_envelope() -> PaymentSignatureEnvelope {
        PaymentSignatureEnvelope {
            scheme: None,
            network: None,
            x402_version: X402_VERSION_V2,
            accepted: Some(challenge().accepts[0].to_accepted_value()),
            resource: Some(ResourceInfo {
                url: "mcp://tool/weather".into(),
                description: None,
                mime_type: None,
            }),
            payload: PaymentProof::Signature {
                signature: "signature".into(),
            },
            extensions: None,
        }
    }

    #[test]
    fn payment_metadata_round_trips() {
        let mut params = serde_json::json!({"name": "weather", "arguments": {}});
        set_payment(&mut params, &payment_envelope()).unwrap();
        let decoded = payment(&params).unwrap().unwrap();
        assert_eq!(decoded["x402Version"], X402_VERSION_V2);
        assert!(params["_meta"].get(PAYMENT_META_KEY).is_some());

        let batch = serde_json::json!({
            "x402Version": 2,
            "accepted": {"scheme": "batch-settlement"},
            "payload": {"voucher": "signed"}
        });
        set_payment(&mut params, &batch).unwrap();
        assert_eq!(payment(&params).unwrap(), Some(batch));
    }

    #[test]
    fn legacy_v1_challenges_and_payments_are_accepted() {
        let result = serde_json::json!({
            "isError": true,
            "structuredContent": {
                "x402Version": 1,
                "error": "Payment required",
                "accepts": [{
                    "scheme": "exact",
                    "network": "solana-devnet",
                    "maxAmountRequired": "1000",
                    "asset": "USDC",
                    "payTo": "11111111111111111111111111111111",
                    "resource": "mcp://tool/weather",
                    "maxTimeoutSeconds": 60
                }]
            },
            "content": []
        });
        let decoded = requirements(&result).unwrap().unwrap();
        assert_eq!(decoded.x402_version, X402_VERSION_V1);
        assert_eq!(decoded.accepts[0].amount, "1000");
        assert_eq!(decoded.accepts[0].resource, "mcp://tool/weather");

        let mut payment = payment_envelope();
        payment.x402_version = X402_VERSION_V1;
        payment.scheme = Some("exact".into());
        payment.network = Some("solana-devnet".into());
        payment.accepted = None;
        payment.resource = None;
        let header =
            base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&payment).unwrap());
        assert_eq!(
            payment_from_header(&header).unwrap()["x402Version"],
            X402_VERSION_V1
        );
    }

    #[test]
    fn challenge_is_emitted_and_read_in_both_required_formats() {
        let result = payment_required(&challenge()).unwrap();
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"],
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap()
        );
        assert_eq!(requirements(&result).unwrap().unwrap().x402_version, 2);

        let fallback = serde_json::json!({
            "content": result["content"].clone(),
            "isError": true
        });
        assert_eq!(requirements(&fallback).unwrap().unwrap().accepts.len(), 1);

        let ordinary = serde_json::json!({
            "content": [{"type": "text", "text": "sunny"}],
            "isError": false
        });
        assert!(requirements(&ordinary).unwrap().is_none());
    }

    #[test]
    fn malformed_metadata_is_not_treated_as_an_unpaid_request() {
        let params = serde_json::json!({"_meta": "not-an-object"});
        assert!(payment(&params).is_err());
    }

    #[test]
    fn settlement_metadata_round_trips_without_clobbering_existing_meta() {
        let mut result = serde_json::json!({
            "content": [],
            "_meta": {"trace": "abc"}
        });
        let settlement =
            SettlementResponse::success("tx-1", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1")
                .with_payer("payer");
        attach_payment_response(&mut result, &settlement).unwrap();
        assert_eq!(result["_meta"]["trace"], "abc");
        assert_eq!(
            payment_response(&result).unwrap(),
            Some(serde_json::to_value(settlement).unwrap())
        );

        let batch = serde_json::json!({
            "success": true,
            "transaction": "",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "extra": {"commitmentId": "commitment-1"}
        });
        attach_payment_response(&mut result, &batch).unwrap();
        assert_eq!(payment_response(&result).unwrap(), Some(batch));
    }

    #[cfg(feature = "server")]
    #[tokio::test]
    async fn exact_gate_returns_a_spec_shaped_unpaid_result() {
        use crate::x402::server::{Config, CurrencyConfig, ExactOptions, X402};

        let payment = X402::new(Config {
            recipient: "11111111111111111111111111111111".into(),
            currencies: vec![CurrencyConfig {
                currency: "USDC".into(),
                decimals: 6,
                token_program: None,
            }],
            network: "devnet".into(),
            resource: "mcp://tool/weather".into(),
            ..Config::default()
        })
        .unwrap();

        let result = payment
            .gate_mcp_exact(
                &serde_json::json!({"name": "weather", "arguments": {}}),
                "0.001",
                ExactOptions::default(),
            )
            .await
            .unwrap();
        let ExactGateResult::PaymentRequired(result) = result else {
            panic!("an unpaid call must return payment requirements");
        };
        assert_eq!(
            requirements(&result).unwrap().unwrap().accepts[0].amount,
            "1000"
        );
    }

    #[cfg(feature = "rmcp")]
    #[test]
    fn rmcp_adapter_uses_x402_metadata_and_dual_format_error() {
        let mut params = ::rmcp::model::CallToolRequestParams::new("weather");
        rmcp::set_payment(&mut params, &payment_envelope()).unwrap();
        assert!(params.meta.as_ref().unwrap().contains_key(PAYMENT_META_KEY));

        let result = rmcp::payment_required(&challenge()).unwrap();
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_some());
        assert_eq!(
            rmcp::requirements(&result).unwrap().unwrap().accepts.len(),
            1
        );
    }
}
