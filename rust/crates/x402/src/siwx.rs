//! Sign-in-with-x helpers for Solana x402 challenges.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use solana_keychain::SolanaSigner;
use solana_signature::Signature;
use url::Url;

use crate::{
    protocol::schemes::exact::{
        PaymentRequiredEnvelope, SOLANA_DEVNET, SOLANA_MAINNET, SOLANA_TESTNET,
    },
    Error, SIGN_IN_WITH_X, SIGN_IN_WITH_X_HEADER, SOLANA_NETWORK,
};

/// Solana SIWX signature type.
pub const SIWX_SIGNATURE_TYPE_ED25519: &str = "ed25519";

/// Solana SIWX signature scheme.
pub const SIWX_SIGNATURE_SCHEME_SIWS: &str = "siws";

const SOLANA_CHAIN_PREFIX: &str = "solana:";
const DEFAULT_MAX_AGE_SECONDS: u64 = 5 * 60;

/// Chain advertised by a sign-in-with-x challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedChain {
    /// CAIP-2 chain identifier.
    pub chain_id: String,
    /// Signature type required for this chain.
    #[serde(rename = "type")]
    pub signature_type: String,
    /// Optional canonical signature scheme hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
}

impl SupportedChain {
    /// Build an Ed25519 SIWS Solana chain entry.
    pub fn solana(chain_id: impl Into<String>) -> Self {
        Self {
            chain_id: chain_id.into(),
            signature_type: SIWX_SIGNATURE_TYPE_ED25519.to_string(),
            signature_scheme: Some(SIWX_SIGNATURE_SCHEME_SIWS.to_string()),
        }
    }
}

/// Server-provided sign-in challenge fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwxExtensionInfo {
    /// Expected HTTP host name for the protected resource.
    pub domain: String,
    /// Expected URI origin for the protected resource.
    pub uri: String,
    /// Human-readable statement to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// SIWS message version.
    pub version: String,
    /// Server-generated nonce.
    pub nonce: String,
    /// RFC3339 issuance time.
    pub issued_at: String,
    /// Optional RFC3339 expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// Optional RFC3339 not-before time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional server request identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional resource list to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
}

/// sign-in-with-x challenge extension carried by x402 payment-required responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwxExtension {
    /// Expected HTTP host name for the protected resource.
    pub domain: String,
    /// Expected URI origin for the protected resource.
    pub uri: String,
    /// Human-readable statement to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// SIWS message version.
    pub version: String,
    /// Server-generated nonce.
    pub nonce: String,
    /// RFC3339 issuance time.
    pub issued_at: String,
    /// Optional RFC3339 expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// Optional RFC3339 not-before time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional server request identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional resource list to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    /// Chains the client may choose to sign for.
    pub supported_chains: Vec<SupportedChain>,
}

impl SiwxExtension {
    /// Build a Solana SIWX extension from server-issued challenge fields.
    pub fn new(info: SiwxExtensionInfo, supported_chains: Vec<SupportedChain>) -> Self {
        Self {
            domain: info.domain,
            uri: info.uri,
            statement: info.statement,
            version: info.version,
            nonce: info.nonce,
            issued_at: info.issued_at,
            expiration_time: info.expiration_time,
            not_before: info.not_before,
            request_id: info.request_id,
            resources: info.resources,
            supported_chains,
        }
    }

    /// Return this extension as a payment-required `extensions` JSON object.
    pub fn as_extensions_value(&self) -> Result<serde_json::Value, Error> {
        Ok(serde_json::json!({
            SIGN_IN_WITH_X: serde_json::to_value(self)
                .map_err(|error| Error::Other(format!("Failed to encode SIWX extension: {error}")))?,
        }))
    }

    /// Parse an SIWX extension from a payment-required `extensions` JSON object.
    pub fn from_extensions_value(extensions: &serde_json::Value) -> Result<Option<Self>, Error> {
        let Some(value) = extensions.get(SIGN_IN_WITH_X) else {
            return Ok(None);
        };
        serde_json::from_value(value.clone())
            .map(Some)
            .map_err(|error| Error::Other(format!("Invalid SIWX extension: {error}")))
    }
}

/// Full SIWX message fields before the signature is attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteSiwxInfo {
    /// Expected HTTP host name for the protected resource.
    pub domain: String,
    /// Signer address.
    pub address: String,
    /// Expected URI origin for the protected resource.
    pub uri: String,
    /// Human-readable statement to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// SIWS message version.
    pub version: String,
    /// CAIP-2 chain identifier selected by the client.
    pub chain_id: String,
    /// Server-generated nonce.
    pub nonce: String,
    /// RFC3339 issuance time.
    pub issued_at: String,
    /// Optional RFC3339 expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// Optional RFC3339 not-before time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional server request identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional resource list to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    /// Signature type used by the client.
    #[serde(rename = "type")]
    pub signature_type: String,
    /// Optional canonical signature scheme hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
}

/// SIWX payload encoded into the SIGN-IN-WITH-X header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwxPayload {
    /// Expected HTTP host name for the protected resource.
    pub domain: String,
    /// Signer address.
    pub address: String,
    /// Expected URI origin for the protected resource.
    pub uri: String,
    /// Human-readable statement to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// SIWS message version.
    pub version: String,
    /// CAIP-2 chain identifier selected by the client.
    pub chain_id: String,
    /// Server-generated nonce.
    pub nonce: String,
    /// RFC3339 issuance time.
    pub issued_at: String,
    /// Optional RFC3339 expiration time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// Optional RFC3339 not-before time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Optional server request identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Optional resource list to include in the signed message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    /// Signature type used by the client.
    #[serde(rename = "type")]
    pub signature_type: String,
    /// Optional canonical signature scheme hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    /// Base58-encoded Ed25519 signature over the SIWS message.
    pub signature: String,
}

impl From<&SiwxPayload> for CompleteSiwxInfo {
    fn from(payload: &SiwxPayload) -> Self {
        Self {
            domain: payload.domain.clone(),
            address: payload.address.clone(),
            uri: payload.uri.clone(),
            statement: payload.statement.clone(),
            version: payload.version.clone(),
            chain_id: payload.chain_id.clone(),
            nonce: payload.nonce.clone(),
            issued_at: payload.issued_at.clone(),
            expiration_time: payload.expiration_time.clone(),
            not_before: payload.not_before.clone(),
            request_id: payload.request_id.clone(),
            resources: payload.resources.clone(),
            signature_type: payload.signature_type.clone(),
            signature_scheme: payload.signature_scheme.clone(),
        }
    }
}

/// Options for selecting a supported chain from an SIWX challenge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiwxChainSelectionOptions {
    /// Preferred CAIP-2 chain identifier or legacy Solana network name.
    pub preferred_chain_id: Option<String>,
    /// Chain identifiers the client is willing to sign for, in preference order.
    pub supported_chain_ids: Vec<String>,
}

/// Options for validating SIWX message metadata.
#[derive(Debug, Clone)]
pub struct SiwxMessageValidationOptions {
    /// Clock used for issuance, expiration, and not-before checks.
    pub now: SystemTime,
    /// Maximum age from issuedAt.
    pub max_age: Duration,
    /// Expected nonce for this challenge.
    pub expected_nonce: Option<String>,
}

impl Default for SiwxMessageValidationOptions {
    fn default() -> Self {
        Self {
            now: SystemTime::now(),
            max_age: Duration::from_secs(DEFAULT_MAX_AGE_SECONDS),
            expected_nonce: None,
        }
    }
}

/// Default Solana SIWX chains advertised by servers.
pub fn default_solana_siwx_chains() -> Vec<SupportedChain> {
    vec![
        SupportedChain::solana(SOLANA_MAINNET),
        SupportedChain::solana(SOLANA_DEVNET),
        SupportedChain::solana(SOLANA_TESTNET),
    ]
}

/// Extract the SIWX extension from a payment-required envelope.
pub fn siwx_extension_from_payment_required(
    envelope: &PaymentRequiredEnvelope,
) -> Result<Option<SiwxExtension>, Error> {
    let Some(extensions) = &envelope.extensions else {
        return Ok(None);
    };
    SiwxExtension::from_extensions_value(extensions)
}

/// Select the Solana SIWX chain a client should sign for.
pub fn select_siwx_chain(
    extension: &SiwxExtension,
    options: &SiwxChainSelectionOptions,
) -> Result<SupportedChain, Error> {
    let compatible_chains: Vec<_> = extension
        .supported_chains
        .iter()
        .filter(|chain| is_compatible_solana_chain(chain))
        .cloned()
        .collect();

    if compatible_chains.is_empty() {
        return Err(Error::Other("siwx_no_compatible_solana_chain".to_string()));
    }

    if let Some(preferred_chain_id) = &options.preferred_chain_id {
        let preferred_chain_id = normalize_siwx_chain_id(preferred_chain_id)?;
        return compatible_chains
            .into_iter()
            .find(|chain| chain.chain_id == preferred_chain_id)
            .ok_or_else(|| Error::Other("siwx_preferred_chain_not_supported".to_string()));
    }

    for chain_id in &options.supported_chain_ids {
        let chain_id = normalize_siwx_chain_id(chain_id)?;
        if let Some(chain) = compatible_chains
            .iter()
            .find(|candidate| candidate.chain_id == chain_id)
        {
            return Ok(chain.clone());
        }
    }

    Ok(compatible_chains[0].clone())
}

/// Format the canonical Sign-In With Solana message.
pub fn format_siws_message(info: &CompleteSiwxInfo) -> Result<String, Error> {
    let chain_reference = extract_solana_chain_reference(&info.chain_id)?;
    let mut lines = vec![
        format!(
            "{} wants you to sign in with your Solana account:",
            info.domain
        ),
        info.address.clone(),
        String::new(),
    ];

    if let Some(statement) = &info.statement {
        lines.push(statement.clone());
        lines.push(String::new());
    }

    lines.push(format!("URI: {}", info.uri));
    lines.push(format!("Version: {}", info.version));
    lines.push(format!("Chain ID: {chain_reference}"));
    lines.push(format!("Nonce: {}", info.nonce));
    lines.push(format!("Issued At: {}", info.issued_at));

    if let Some(expiration_time) = &info.expiration_time {
        lines.push(format!("Expiration Time: {expiration_time}"));
    }
    if let Some(not_before) = &info.not_before {
        lines.push(format!("Not Before: {not_before}"));
    }
    if let Some(request_id) = &info.request_id {
        lines.push(format!("Request ID: {request_id}"));
    }
    if let Some(resources) = &info.resources {
        if !resources.is_empty() {
            lines.push("Resources:".to_string());
            for resource in resources {
                lines.push(format!("- {resource}"));
            }
        }
    }

    Ok(lines.join("\n"))
}

/// Extract the SIWS chain reference from a Solana CAIP-2 identifier.
pub fn extract_solana_chain_reference(chain_id: &str) -> Result<&str, Error> {
    chain_id
        .strip_prefix(SOLANA_CHAIN_PREFIX)
        .ok_or_else(|| Error::Other("siwx_unsupported_chain".to_string()))
}

/// Create a signed SIWX payload for a selected chain.
pub async fn create_siwx_payload<S: SolanaSigner + ?Sized>(
    info: &SiwxExtension,
    chain: &SupportedChain,
    signer: &S,
) -> Result<SiwxPayload, Error> {
    let address = signer.pubkey().to_string();
    let complete_info = CompleteSiwxInfo {
        domain: info.domain.clone(),
        address: address.clone(),
        uri: info.uri.clone(),
        statement: info.statement.clone(),
        version: info.version.clone(),
        chain_id: chain.chain_id.clone(),
        nonce: info.nonce.clone(),
        issued_at: info.issued_at.clone(),
        expiration_time: info.expiration_time.clone(),
        not_before: info.not_before.clone(),
        request_id: info.request_id.clone(),
        resources: info.resources.clone(),
        signature_type: chain.signature_type.clone(),
        signature_scheme: chain.signature_scheme.clone(),
    };
    let message = format_siws_message(&complete_info)?;
    let signature = signer
        .sign_message(message.as_bytes())
        .await
        .map_err(|error| Error::Other(format!("Failed to sign SIWX message: {error}")))?;

    Ok(SiwxPayload {
        domain: complete_info.domain,
        address,
        uri: complete_info.uri,
        statement: complete_info.statement,
        version: complete_info.version,
        chain_id: complete_info.chain_id,
        nonce: complete_info.nonce,
        issued_at: complete_info.issued_at,
        expiration_time: complete_info.expiration_time,
        not_before: complete_info.not_before,
        request_id: complete_info.request_id,
        resources: complete_info.resources,
        signature_type: complete_info.signature_type,
        signature_scheme: complete_info.signature_scheme,
        signature: signature.to_string(),
    })
}

/// Create the SIGN-IN-WITH-X header for a selected SIWX challenge.
pub async fn create_siwx_header<S: SolanaSigner + ?Sized>(
    info: &SiwxExtension,
    chain: &SupportedChain,
    signer: &S,
) -> Result<String, Error> {
    encode_siwx_header(&create_siwx_payload(info, chain, signer).await?)
}

/// Encode a signed SIWX payload for the SIGN-IN-WITH-X header.
pub fn encode_siwx_header(payload: &SiwxPayload) -> Result<String, Error> {
    let json = serde_json::to_vec(payload)
        .map_err(|error| Error::Other(format!("Failed to encode SIWX payload: {error}")))?;
    Ok(BASE64_STANDARD.encode(json))
}

/// Decode a SIGN-IN-WITH-X header into a signed SIWX payload.
pub fn parse_siwx_header(header: &str) -> Result<SiwxPayload, Error> {
    let decoded = BASE64_STANDARD
        .decode(header)
        .map_err(|error| Error::Other(format!("Invalid SIWX header: {error}")))?;
    serde_json::from_slice(&decoded)
        .map_err(|error| Error::Other(format!("Invalid SIWX payload: {error}")))
}

/// Verify the Ed25519 signature on a signed SIWX payload.
pub fn verify_siwx_payload(payload: &SiwxPayload) -> Result<bool, Error> {
    let info = CompleteSiwxInfo::from(payload);
    if !is_compatible_solana_payload(payload) {
        return Ok(false);
    }

    let public_key_bytes = bs58::decode(&payload.address)
        .into_vec()
        .map_err(|error| Error::Other(format!("Invalid SIWX address: {error}")))?;
    let signature_bytes = bs58::decode(&payload.signature)
        .into_vec()
        .map_err(|error| Error::Other(format!("Invalid SIWX signature: {error}")))?;
    let signature_bytes: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Other("siwx_invalid_signature".to_string()))?;
    if public_key_bytes.len() != 32 {
        return Err(Error::Other("siwx_invalid_address".to_string()));
    }

    let signature = Signature::from(signature_bytes);
    Ok(signature.verify(
        public_key_bytes.as_slice(),
        format_siws_message(&info)?.as_bytes(),
    ))
}

/// Validate SIWX domain, URI, nonce, and time bounds.
pub fn validate_siwx_message(
    payload: &SiwxPayload,
    expected_resource_uri: &str,
    options: &SiwxMessageValidationOptions,
) -> Result<(), Error> {
    let expected_url = Url::parse(expected_resource_uri)
        .map_err(|error| Error::Other(format!("Invalid expected resource URI: {error}")))?;
    let payload_url = Url::parse(&payload.uri)
        .map_err(|error| Error::Other(format!("Invalid SIWX URI: {error}")))?;

    if payload.domain != expected_url.host_str().unwrap_or_default() {
        return Err(Error::Other("siwx_domain_mismatch".to_string()));
    }
    if payload_url.origin().ascii_serialization() != expected_url.origin().ascii_serialization() {
        return Err(Error::Other("siwx_uri_origin_mismatch".to_string()));
    }
    if let Some(expected_nonce) = &options.expected_nonce {
        if &payload.nonce != expected_nonce {
            return Err(Error::Other("siwx_nonce_mismatch".to_string()));
        }
    }

    let issued_at = parse_rfc3339_z(&payload.issued_at)?;
    if issued_at > options.now {
        return Err(Error::Other("siwx_issued_at_in_future".to_string()));
    }
    if options
        .now
        .duration_since(issued_at)
        .map_err(|_| Error::Other("siwx_issued_at_in_future".to_string()))?
        > options.max_age
    {
        return Err(Error::Other("siwx_issued_at_too_old".to_string()));
    }
    if let Some(expiration_time) = &payload.expiration_time {
        if parse_rfc3339_z(expiration_time)? <= options.now {
            return Err(Error::Other("siwx_expired".to_string()));
        }
    }
    if let Some(not_before) = &payload.not_before {
        if parse_rfc3339_z(not_before)? > options.now {
            return Err(Error::Other("siwx_not_before".to_string()));
        }
    }

    Ok(())
}

/// Return the canonical SIWX header name.
pub fn siwx_header_name() -> &'static str {
    SIGN_IN_WITH_X_HEADER
}

fn normalize_siwx_chain_id(chain_id: &str) -> Result<String, Error> {
    Ok(match chain_id {
        SOLANA_NETWORK | "mainnet" | "mainnet-beta" => SOLANA_MAINNET.to_string(),
        "solana-devnet" | "devnet" | "localnet" => SOLANA_DEVNET.to_string(),
        "solana-testnet" | "testnet" => SOLANA_TESTNET.to_string(),
        value if value.starts_with(SOLANA_CHAIN_PREFIX) => value.to_string(),
        _ => return Err(Error::Other("siwx_unsupported_chain".to_string())),
    })
}

fn is_compatible_solana_chain(chain: &SupportedChain) -> bool {
    chain.chain_id.starts_with(SOLANA_CHAIN_PREFIX)
        && chain.signature_type == SIWX_SIGNATURE_TYPE_ED25519
        && chain
            .signature_scheme
            .as_deref()
            .unwrap_or(SIWX_SIGNATURE_SCHEME_SIWS)
            == SIWX_SIGNATURE_SCHEME_SIWS
}

fn is_compatible_solana_payload(payload: &SiwxPayload) -> bool {
    payload.chain_id.starts_with(SOLANA_CHAIN_PREFIX)
        && payload.signature_type == SIWX_SIGNATURE_TYPE_ED25519
        && payload
            .signature_scheme
            .as_deref()
            .unwrap_or(SIWX_SIGNATURE_SCHEME_SIWS)
            == SIWX_SIGNATURE_SCHEME_SIWS
}

fn parse_rfc3339_z(value: &str) -> Result<SystemTime, Error> {
    let value = value
        .strip_suffix('Z')
        .ok_or_else(|| Error::Other("siwx_invalid_timestamp".to_string()))?;
    let (date, time) = value
        .split_once('T')
        .ok_or_else(|| Error::Other("siwx_invalid_timestamp".to_string()))?;
    let mut date_parts = date.split('-');
    let year = parse_i32(date_parts.next(), "siwx_invalid_timestamp")?;
    let month = parse_u32(date_parts.next(), "siwx_invalid_timestamp")?;
    let day = parse_u32(date_parts.next(), "siwx_invalid_timestamp")?;
    if date_parts.next().is_some() {
        return Err(Error::Other("siwx_invalid_timestamp".to_string()));
    }

    let (time, _) = time.split_once('.').unwrap_or((time, ""));
    let mut time_parts = time.split(':');
    let hour = parse_u32(time_parts.next(), "siwx_invalid_timestamp")?;
    let minute = parse_u32(time_parts.next(), "siwx_invalid_timestamp")?;
    let second = parse_u32(time_parts.next(), "siwx_invalid_timestamp")?;
    if time_parts.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(Error::Other("siwx_invalid_timestamp".to_string()));
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add((hour * 3_600 + minute * 60 + second) as i64))
        .ok_or_else(|| Error::Other("siwx_invalid_timestamp".to_string()))?;

    if seconds >= 0 {
        Ok(UNIX_EPOCH + Duration::from_secs(seconds as u64))
    } else {
        Ok(UNIX_EPOCH - Duration::from_secs(seconds.unsigned_abs()))
    }
}

fn parse_i32(value: Option<&str>, error: &str) -> Result<i32, Error> {
    value
        .ok_or_else(|| Error::Other(error.to_string()))?
        .parse()
        .map_err(|_| Error::Other(error.to_string()))
}

fn parse_u32(value: Option<&str>, error: &str) -> Result<u32, Error> {
    value
        .ok_or_else(|| Error::Other(error.to_string()))?
        .parse()
        .map_err(|_| Error::Other(error.to_string()))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i32;
    let day = day as i32;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_keychain::memory::MemorySigner;

    const TEST_KEYPAIR_BYTES: [u8; 64] = [
        41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254, 227, 176, 196, 204,
        122, 47, 166, 133, 155, 252, 217, 0, 253, 17, 49, 143, 47, 94, 121, 167, 195, 136, 72, 22,
        157, 48, 77, 88, 63, 96, 57, 122, 181, 243, 236, 188, 241, 134, 174, 224, 100, 246, 17,
        170, 104, 17, 151, 48,
    ];

    fn challenge() -> SiwxExtension {
        SiwxExtension::new(
            SiwxExtensionInfo {
                domain: "example.com".to_string(),
                uri: "https://example.com/reports".to_string(),
                statement: Some("Sign in to use this endpoint.".to_string()),
                version: "1".to_string(),
                nonce: "nonce-123".to_string(),
                issued_at: "2026-04-27T00:00:00Z".to_string(),
                expiration_time: Some("2026-04-27T00:10:00Z".to_string()),
                not_before: None,
                request_id: Some("request-123".to_string()),
                resources: Some(vec!["https://example.com/reports".to_string()]),
            },
            default_solana_siwx_chains(),
        )
    }

    #[test]
    fn formats_siws_message_like_canonical_solana() {
        let info = CompleteSiwxInfo {
            domain: "example.com".to_string(),
            address: "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR".to_string(),
            uri: "https://example.com/reports".to_string(),
            statement: Some("Sign in to use this endpoint.".to_string()),
            version: "1".to_string(),
            chain_id: SOLANA_DEVNET.to_string(),
            nonce: "nonce-123".to_string(),
            issued_at: "2026-04-27T00:00:00Z".to_string(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: None,
            signature_type: SIWX_SIGNATURE_TYPE_ED25519.to_string(),
            signature_scheme: Some(SIWX_SIGNATURE_SCHEME_SIWS.to_string()),
        };

        assert_eq!(
            format_siws_message(&info).unwrap(),
            "example.com wants you to sign in with your Solana account:\n\
4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR\n\n\
Sign in to use this endpoint.\n\n\
URI: https://example.com/reports\n\
Version: 1\n\
Chain ID: EtWTRABZaYq6iMfeYKouRu166VU2xqa1\n\
Nonce: nonce-123\n\
Issued At: 2026-04-27T00:00:00Z"
        );
    }

    #[test]
    fn selects_preferred_chain() {
        let chain = select_siwx_chain(
            &challenge(),
            &SiwxChainSelectionOptions {
                preferred_chain_id: Some("solana-devnet".to_string()),
                supported_chain_ids: vec![],
            },
        )
        .unwrap();

        assert_eq!(chain.chain_id, SOLANA_DEVNET);
    }

    #[test]
    fn rejects_incompatible_or_unsupported_chain_selection() {
        let evm_only = SiwxExtension::new(
            SiwxExtensionInfo {
                domain: "example.com".to_string(),
                uri: "https://example.com/reports".to_string(),
                statement: None,
                version: "1".to_string(),
                nonce: "nonce-123".to_string(),
                issued_at: "2026-04-27T00:00:00Z".to_string(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: None,
            },
            vec![SupportedChain {
                chain_id: "eip155:8453".to_string(),
                signature_type: SIWX_SIGNATURE_TYPE_ED25519.to_string(),
                signature_scheme: Some(SIWX_SIGNATURE_SCHEME_SIWS.to_string()),
            }],
        );
        let error =
            select_siwx_chain(&evm_only, &SiwxChainSelectionOptions::default()).unwrap_err();
        assert!(error
            .to_string()
            .contains("siwx_no_compatible_solana_chain"));

        let error = select_siwx_chain(
            &challenge(),
            &SiwxChainSelectionOptions {
                preferred_chain_id: Some("solana:unknown".to_string()),
                supported_chain_ids: vec![],
            },
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("siwx_preferred_chain_not_supported"));
    }

    #[tokio::test]
    async fn signs_encodes_parses_and_verifies_payload() {
        let signer = MemorySigner::from_bytes(&TEST_KEYPAIR_BYTES).unwrap();
        let challenge = challenge();
        let chain = select_siwx_chain(
            &challenge,
            &SiwxChainSelectionOptions {
                preferred_chain_id: Some(SOLANA_DEVNET.to_string()),
                supported_chain_ids: vec![],
            },
        )
        .unwrap();

        let payload = create_siwx_payload(&challenge, &chain, &signer)
            .await
            .unwrap();
        let header = encode_siwx_header(&payload).unwrap();
        let parsed = parse_siwx_header(&header).unwrap();

        assert_eq!(payload, parsed);
        assert!(verify_siwx_payload(&parsed).unwrap());
        assert_eq!(siwx_header_name(), SIGN_IN_WITH_X_HEADER);
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut payload = SiwxPayload {
            domain: "example.com".to_string(),
            address: "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR".to_string(),
            uri: "https://example.com/reports".to_string(),
            statement: None,
            version: "1".to_string(),
            chain_id: SOLANA_DEVNET.to_string(),
            nonce: "nonce-123".to_string(),
            issued_at: "2026-04-27T00:00:00Z".to_string(),
            expiration_time: None,
            not_before: None,
            request_id: None,
            resources: None,
            signature_type: SIWX_SIGNATURE_TYPE_ED25519.to_string(),
            signature_scheme: Some(SIWX_SIGNATURE_SCHEME_SIWS.to_string()),
            signature: bs58::encode([1_u8; 64]).into_string(),
        };

        assert!(!verify_siwx_payload(&payload).unwrap());
        payload.signature_type = "eip191".to_string();
        assert!(!verify_siwx_payload(&payload).unwrap());
    }

    #[test]
    fn validates_message_metadata() {
        let payload = SiwxPayload {
            domain: "example.com".to_string(),
            address: "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR".to_string(),
            uri: "https://example.com/reports".to_string(),
            statement: None,
            version: "1".to_string(),
            chain_id: SOLANA_DEVNET.to_string(),
            nonce: "nonce-123".to_string(),
            issued_at: "2026-04-27T00:00:00Z".to_string(),
            expiration_time: Some("2026-04-27T00:10:00Z".to_string()),
            not_before: None,
            request_id: None,
            resources: None,
            signature_type: SIWX_SIGNATURE_TYPE_ED25519.to_string(),
            signature_scheme: Some(SIWX_SIGNATURE_SCHEME_SIWS.to_string()),
            signature: bs58::encode([1_u8; 64]).into_string(),
        };
        let options = SiwxMessageValidationOptions {
            now: parse_rfc3339_z("2026-04-27T00:01:00Z").unwrap(),
            max_age: Duration::from_secs(300),
            expected_nonce: Some("nonce-123".to_string()),
        };

        validate_siwx_message(&payload, "https://example.com/reports/usage", &options).unwrap();

        let error = validate_siwx_message(&payload, "https://api.example.com/reports", &options)
            .unwrap_err();
        assert!(error.to_string().contains("siwx_domain_mismatch"));

        let error =
            validate_siwx_message(&payload, "https://example.org/reports", &options).unwrap_err();
        assert!(error.to_string().contains("siwx_domain_mismatch"));

        let mut origin_mismatch = payload.clone();
        origin_mismatch.domain = "example.com".to_string();
        origin_mismatch.uri = "https://auth.example.com/reports".to_string();
        let error =
            validate_siwx_message(&origin_mismatch, "https://example.com/reports", &options)
                .unwrap_err();
        assert!(error.to_string().contains("siwx_uri_origin_mismatch"));

        let mut future = payload.clone();
        future.issued_at = "2026-04-27T00:02:00Z".to_string();
        let error =
            validate_siwx_message(&future, "https://example.com/reports", &options).unwrap_err();
        assert!(error.to_string().contains("siwx_issued_at_in_future"));

        let mut expired = payload.clone();
        expired.expiration_time = Some("2026-04-27T00:01:00Z".to_string());
        let error =
            validate_siwx_message(&expired, "https://example.com/reports", &options).unwrap_err();
        assert!(error.to_string().contains("siwx_expired"));

        let mut not_before = payload;
        not_before.not_before = Some("2026-04-27T00:02:00Z".to_string());
        let error = validate_siwx_message(&not_before, "https://example.com/reports", &options)
            .unwrap_err();
        assert!(error.to_string().contains("siwx_not_before"));
    }

    #[test]
    fn builds_extension_value() {
        let value = challenge().as_extensions_value().unwrap();
        let parsed = SiwxExtension::from_extensions_value(&value)
            .unwrap()
            .unwrap();
        let envelope = PaymentRequiredEnvelope {
            x402_version: crate::X402_VERSION_V2,
            resource: None,
            accepts: vec![],
            error: None,
            extensions: Some(value),
        };
        let parsed_from_envelope = siwx_extension_from_payment_required(&envelope)
            .unwrap()
            .unwrap();

        assert_eq!(parsed.nonce, "nonce-123");
        assert_eq!(parsed_from_envelope.nonce, "nonce-123");
    }

    #[test]
    fn handles_missing_and_invalid_extension_values() {
        let envelope = PaymentRequiredEnvelope {
            x402_version: crate::X402_VERSION_V2,
            resource: None,
            accepts: vec![],
            error: None,
            extensions: None,
        };
        assert!(siwx_extension_from_payment_required(&envelope)
            .unwrap()
            .is_none());
        assert!(SiwxExtension::from_extensions_value(&serde_json::json!({}))
            .unwrap()
            .is_none());

        let invalid = serde_json::json!({
            SIGN_IN_WITH_X: {
                "domain": "example.com",
                "uri": "https://example.com",
                "version": "1",
                "issuedAt": "2026-04-27T00:00:00Z",
                "supportedChains": []
            }
        });
        let error = SiwxExtension::from_extensions_value(&invalid).unwrap_err();
        assert!(error.to_string().contains("Invalid SIWX extension"));
    }
}
