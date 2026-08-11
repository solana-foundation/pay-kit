//! Session intent request and voucher types.
//!
//! The session intent opens a payment channel between a client and server,
//! allowing incremental payments via off-chain signed vouchers backed by
//! the on-chain payment-channels program.

use serde::{Deserialize, Serialize};

/// Default session voucher/directive expiry: 2100-01-01T00:00:00Z.
///
/// This stays below JavaScript's max safe integer so JSON intermediaries do not
/// round it before the credential is decoded.
pub const DEFAULT_SESSION_EXPIRES_AT: i64 = 4_102_444_800;
/// Maximum negotiated idle timeout (30 days), in seconds.
pub const MAX_IDLE_TIMEOUT_SECONDS: u32 = 2_592_000;
/// Domain separator for reusable session authentication proofs.
pub const SESSION_AUTHENTICATION_DOMAIN: &str = "mpp-session-auth-v1";

fn serialize_u64_as_string<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_u64_from_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer)?
        .parse::<u64>()
        .map_err(serde::de::Error::custom)
}

fn serialize_opt_u64_as_string<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serializer.serialize_str(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_opt_u64_from_string<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| value.parse::<u64>().map_err(serde::de::Error::custom))
        .transpose()
}

/// Who holds voucher signing authority for the payment channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum SessionVoucherSigner {
    /// A payer-controlled key signs each cumulative voucher.
    #[default]
    Client,
    /// The operator meters usage and signs cumulative vouchers after verifying
    /// the payer's reusable session proof.
    Operator,
}

/// Reusable payer proof bound to one challenge and channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionAuthentication {
    /// Always `proof` on the wire.
    #[serde(rename = "type")]
    pub kind: SessionAuthenticationType,
    /// Session challenge identifier signed into the proof.
    pub challenge_id: String,
    /// Payer public key (base58).
    pub payer: String,
    /// Ed25519 signature over the canonical authentication message (base58).
    pub signature: String,
}

/// Discriminator for a reusable session proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionAuthenticationType {
    /// An Ed25519 payer proof.
    Proof,
}

impl SessionAuthentication {
    /// Create a reusable proof with an Ed25519 signing key.
    pub fn sign(
        challenge_id: impl Into<String>,
        channel_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> crate::mpp::error::Result<Self> {
        use ed25519_dalek::Signer;

        let mut authentication = Self {
            kind: SessionAuthenticationType::Proof,
            challenge_id: challenge_id.into(),
            payer: bs58::encode(signing_key.verifying_key().as_bytes()).into_string(),
            signature: String::new(),
        };
        authentication.signature = bs58::encode(
            signing_key
                .sign(&authentication.message_bytes(channel_id)?)
                .to_bytes(),
        )
        .into_string();
        Ok(authentication)
    }

    /// Return the RFC 8785/JCS message bytes signed by the payer.
    pub fn message_bytes(&self, channel_id: &str) -> crate::mpp::error::Result<Vec<u8>> {
        let value = serde_json::json!({
            "channelId": channel_id,
            "domain": SESSION_AUTHENTICATION_DOMAIN,
            "payer": self.payer,
            "sessionChallengeId": self.challenge_id,
        });
        serde_json_canonicalizer::to_vec(&value)
            .map_err(|error| crate::mpp::error::Error::Other(error.to_string()))
    }

    /// Verify this proof against its payer and bound channel.
    pub fn verify(&self, channel_id: &str) -> crate::mpp::error::Result<bool> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let payer: [u8; 32] = bs58::decode(&self.payer)
            .into_vec()
            .map_err(|error| crate::mpp::error::Error::Other(error.to_string()))?
            .try_into()
            .map_err(|_| crate::mpp::error::Error::Other("payer must be 32 bytes".to_string()))?;
        let signature: [u8; 64] = bs58::decode(&self.signature)
            .into_vec()
            .map_err(|error| crate::mpp::error::Error::Other(error.to_string()))?
            .try_into()
            .map_err(|_| {
                crate::mpp::error::Error::Other("signature must be 64 bytes".to_string())
            })?;
        let key = VerifyingKey::from_bytes(&payer)
            .map_err(|error| crate::mpp::error::Error::Other(error.to_string()))?;
        Ok(key
            .verify(
                &self.message_bytes(channel_id)?,
                &Signature::from_bytes(&signature),
            )
            .is_ok())
    }
}

/// Session intent request — the payload embedded in a 402 challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRequest {
    /// Price per unit of service, in base units.
    pub amount: String,
    pub currency: String,
    pub recipient: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_deposit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_deposit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_type: Option<String>,
    pub method_details: SessionMethodDetails,
}

/// Solana-specific session policy nested under `methodDetails`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionMethodDetails {
    pub network: String,
    pub channel_program: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    /// Base58 blockhash the client MUST use as the open transaction's recent
    /// blockhash. Conditionally REQUIRED when `channel_id` is absent (new
    /// channel); MUST be absent when resuming an existing channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,
    /// RPC context slot from the same `getLatestBlockhash` response as
    /// `recent_blockhash` — the client's default `openSlot` (an earlier slot
    /// is allowed, a later one is rejected). Same conditionality as
    /// `recent_blockhash`. Decimal string on the wire.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_opt_u64_as_string",
        deserialize_with = "deserialize_opt_u64_from_string"
    )]
    pub recent_slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_payer_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_signer: Option<SessionVoucherSigner>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_options_seconds: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grace_period_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distribution_splits: Vec<SessionSplit>,
}

/// A payment split committed at channel open; distributed to a specific
/// recipient when the channel closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSplit {
    /// Recipient address (base58).
    pub recipient: String,

    /// Share in basis points.
    pub share_bps: u16,
}

// ── Client actions ──

/// The action submitted by the client in an Authorization header.
///
/// Serialized as a tagged object with `"action": "open" | "voucher" | "use" | "topUp" | "close"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
// `Open` is inherently the big variant (the full channel-open wire payload);
// boxing it would ripple through every constructor/match on this public wire
// enum for a type that is built a handful of times per session.
#[allow(clippy::large_enum_variant)]
pub enum SessionAction {
    /// Open a new channel/delegation and start the session.
    Open(OpenPayload),

    /// Submit a signed voucher authorizing payment for an API call.
    Voucher(VoucherPayload),

    /// Use an operator-signed session with its reusable payer proof.
    Use(UsePayload),

    /// Top up an existing channel's deposit.
    TopUp(TopUpPayload),

    /// Request cooperative close of the channel.
    Close(ClosePayload),
}

/// Exact payment-channel `open` credential payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenPayload {
    pub channel_id: String,
    pub payer: String,
    pub payee: String,
    pub mint: String,
    pub authorized_signer: String,
    #[serde(
        deserialize_with = "deserialize_u64_from_string",
        serialize_with = "serialize_u64_as_string"
    )]
    pub salt: u64,
    pub deposit_amount: String,
    pub grace_period_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout_seconds: Option<u32>,
    #[serde(
        deserialize_with = "deserialize_u64_from_string",
        serialize_with = "serialize_u64_as_string"
    )]
    pub open_slot: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub distribution_splits: Vec<SessionSplit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_policy: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SessionAuthentication>,
    pub transaction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
}

/// Literal intent discriminator required on Solana session receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionReceiptIntent {
    /// The receipt records a payment-channel session action.
    #[serde(rename = "session")]
    Session,
}

/// Fields added to the standard receipt for every session action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionReceiptExtensions {
    /// Intent discriminator; always serializes as `"session"`.
    pub intent: SessionReceiptIntent,
    /// Highest cumulative voucher accepted by the server, in base units.
    #[serde(
        deserialize_with = "deserialize_u64_from_string",
        serialize_with = "serialize_u64_as_string"
    )]
    pub accepted_cumulative: u64,
    /// Total value already consumed by delivered work, in base units.
    #[serde(
        deserialize_with = "deserialize_u64_from_string",
        serialize_with = "serialize_u64_as_string"
    )]
    pub spent: u64,
    /// Effective inactivity threshold negotiated for the channel.
    pub idle_timeout_seconds: u32,
    /// Settlement transaction signature returned by a close action, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Amount returned to the payer after distribution, when known.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_opt_u64_from_string",
        serialize_with = "serialize_opt_u64_as_string"
    )]
    pub refunded: Option<u64>,
}

impl OpenPayload {
    /// Construct a payment-channel open payload.
    #[allow(clippy::too_many_arguments)]
    pub fn payment_channel(
        channel_id: String,
        deposit_amount: String,
        payer: String,
        payee: String,
        mint: String,
        salt: u64,
        grace_period_seconds: u32,
        open_slot: u64,
        authorized_signer: String,
        transaction: String,
    ) -> Self {
        Self {
            channel_id,
            deposit_amount,
            payer,
            payee,
            mint,
            salt,
            grace_period_seconds,
            open_slot,
            authorized_signer,
            transaction,
            distribution_splits: vec![],
            authorization_policy: None,
            authentication: None,
            idle_timeout_seconds: None,
            capabilities: None,
        }
    }

    /// Bind a reusable payer proof to an operator-signed open.
    pub fn with_authentication(mut self, authentication: SessionAuthentication) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Select one of the challenge's offered inactivity thresholds.
    pub fn with_idle_timeout(mut self, seconds: u32) -> Self {
        self.idle_timeout_seconds = Some(seconds);
        self
    }

    pub fn session_id(&self) -> &str {
        &self.channel_id
    }

    pub fn deposit_amount(&self) -> crate::mpp::error::Result<u64> {
        self.deposit_amount.parse().map_err(|_| {
            crate::mpp::error::Error::Other(format!(
                "invalid deposit amount: {}",
                self.deposit_amount
            ))
        })
    }
}

/// Payload for the `voucher` action (per-request micropayment).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherPayload {
    /// The channel/session ID this voucher is submitted against (base58).
    ///
    /// REQUIRED routing key next to the signed voucher; servers MUST reject
    /// the action when it differs from the signed voucher's inner
    /// `channelId` — the routing key must never diverge from the signed
    /// content.
    pub channel_id: String,

    /// The signed voucher authorizing cumulative spend.
    pub voucher: SignedVoucher,
}

/// Server-issued metering directive attached to a delivered message/response.
///
/// Clients treat this like an offset in a message log: once the message has
/// been processed successfully, `ack`/`commit` signs a voucher for `amount`
/// and sends [`CommitPayload`] back to the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeteringDirective {
    /// Server-generated idempotency key for this delivery.
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,

    /// Channel/session ID this delivery belongs to.
    #[serde(rename = "sessionId")]
    pub session_id: String,

    /// Amount owed for this delivery in base units.
    pub amount: String,

    /// Currency/asset identifier (e.g., "USDC", mint address).
    pub currency: String,

    /// Monotonic per-session delivery sequence.
    pub sequence: u64,

    /// Unix timestamp after which this directive should not be committed.
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,

    /// Optional commit endpoint hint for HTTP transports.
    #[serde(rename = "commitUrl", skip_serializing_if = "Option::is_none")]
    pub commit_url: Option<String>,

    /// Optional server proof or opaque metadata for transport integrations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
}

impl MeteringDirective {
    /// Parse `amount` as base units.
    pub fn amount_base_units(&self) -> crate::mpp::error::Result<u64> {
        self.amount.parse().map_err(|_| {
            crate::mpp::error::Error::Other(format!("invalid metering amount: {}", self.amount))
        })
    }
}

/// Final usage reported by a streaming response.
///
/// The amount MUST be less than or equal to the amount reserved by the original
/// [`MeteringDirective`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeteringUsage {
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,

    /// Final amount owed for this stream in base units.
    pub amount: String,
}

impl MeteringUsage {
    pub fn amount_base_units(&self) -> crate::mpp::error::Result<u64> {
        self.amount.parse().map_err(|_| {
            crate::mpp::error::Error::Other(format!(
                "invalid metering usage amount: {}",
                self.amount
            ))
        })
    }
}

/// A payload paired with the metering directive required to acknowledge it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeteredEnvelope<T> {
    pub payload: T,
    pub metering: MeteringDirective,
}

/// Payload for the `commit` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitPayload {
    /// Delivery id from the original [`MeteringDirective`].
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,

    /// Signed voucher authorizing the delivery amount.
    pub voucher: SignedVoucher,
}

/// Result returned after a delivery commit is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitReceipt {
    #[serde(rename = "deliveryId")]
    pub delivery_id: String,

    #[serde(rename = "sessionId")]
    pub session_id: String,

    /// Amount committed for this delivery in base units.
    pub amount: String,

    /// New settled cumulative watermark in base units.
    pub cumulative: String,

    pub status: CommitStatus,
}

/// Commit receipt status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CommitStatus {
    /// First successful commit for the delivery.
    Committed,

    /// Idempotent replay of a previously accepted commit.
    Replayed,
}

/// Payload for the `topUp` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopUpPayload {
    pub channel_id: String,
    /// Amount added to the existing deposit (base units).
    pub additional_amount: String,
    /// Signed top-up transaction (base64).
    pub transaction: String,
}

/// Payload for the `close` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClosePayload {
    /// The on-chain channel address (base58).
    pub channel_id: String,

    /// Reusable payer proof required for operator-signed vouchers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<SessionAuthentication>,

    /// Final signed voucher for any remaining balance owed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher: Option<SignedVoucher>,
}

/// Payload for a billable request in operator-signed mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsePayload {
    /// Channel identifier (base58).
    pub channel_id: String,
    /// Reusable payer proof bound at channel open.
    pub authentication: SessionAuthentication,
}

/// Validate an offered idle-timeout list.
pub fn validate_idle_timeout_options(options: &[u32]) -> crate::mpp::error::Result<()> {
    if options.is_empty() {
        return Err(crate::mpp::error::Error::Other(
            "idleTimeoutOptionsSeconds must not be empty".to_string(),
        ));
    }
    let mut previous = 0;
    for &value in options {
        if value == 0 || value > MAX_IDLE_TIMEOUT_SECONDS {
            return Err(crate::mpp::error::Error::Other(format!(
                "idle timeout must be between 1 and {MAX_IDLE_TIMEOUT_SECONDS}"
            )));
        }
        if value <= previous {
            return Err(crate::mpp::error::Error::Other(
                "idleTimeoutOptionsSeconds must be strictly increasing".to_string(),
            ));
        }
        previous = value;
    }
    Ok(())
}

/// Resolve the effective timeout while rejecting unsupported selections.
pub fn resolve_idle_timeout_seconds(
    default_seconds: u32,
    options: Option<&[u32]>,
    selected: Option<u32>,
) -> crate::mpp::error::Result<u32> {
    if default_seconds == 0 || default_seconds > MAX_IDLE_TIMEOUT_SECONDS {
        return Err(crate::mpp::error::Error::Other(format!(
            "default idle timeout must be between 1 and {MAX_IDLE_TIMEOUT_SECONDS}"
        )));
    }
    if let Some(options) = options {
        validate_idle_timeout_options(options)?;
    }
    match selected {
        Some(value) => match options {
            Some(options) if options.contains(&value) => Ok(value),
            Some(_) => Err(crate::mpp::error::Error::Other(
                "idleTimeoutSeconds was not one of the advertised options".to_string(),
            )),
            None => Err(crate::mpp::error::Error::Other(
                "idleTimeoutSeconds is not allowed when no options were advertised".to_string(),
            )),
        },
        None => Ok(options
            .and_then(|values| {
                values
                    .contains(&default_seconds)
                    .then_some(default_seconds)
                    .or(values.first().copied())
            })
            .unwrap_or(default_seconds)),
    }
}

// ── Vouchers ──

/// A signed voucher authorizing cumulative payment up to `cumulative`.
///
/// Vouchers are **cumulative**: the server always uses the latest valid voucher
/// it has received. The client MUST increment `cumulative` with each request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedVoucher {
    /// The voucher content, carried on the wire as `voucher` per the spec's
    /// Signed Voucher table (mpp-specs e702dd8).
    #[serde(rename = "voucher")]
    pub data: VoucherData,

    /// Base58 public key that signed the voucher.
    pub signer: String,

    /// Ed25519 signature over the payment-channel Borsh voucher bytes (base58).
    pub signature: String,

    /// Signature algorithm; the session contract currently permits Ed25519 only.
    pub signature_type: VoucherSignatureType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VoucherSignatureType {
    Ed25519,
}

/// The canonical content of a voucher, signed by the client's session key.
///
/// Serialized as the on-chain `VoucherArgs` layout before signing:
/// `magic(0x56 0x01) || channel_id || cumulative_amount_le || expires_at_le`
/// (50 bytes). The magic prefix exists only in the signed bytes — it is never
/// carried in the JSON voucher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherData {
    /// The channel/session ID this voucher is bound to (base58).
    ///
    pub channel_id: String,

    /// Cumulative amount authorized (base units, monotonically increasing).
    pub cumulative_amount: String,

    /// Unix timestamp at which this voucher expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl VoucherData {
    /// Serialize to the payment-channels `VoucherArgs` bytes signed by Ed25519.
    pub fn message_bytes(&self) -> crate::mpp::error::Result<Vec<u8>> {
        let channel_id = crate::mpp::program::payment_channels::parse_pubkey(&self.channel_id)?;
        let cumulative = self.cumulative_amount.parse().map_err(|_| {
            crate::mpp::error::Error::Other("invalid voucher cumulative".to_string())
        })?;
        Ok(
            crate::mpp::program::payment_channels::voucher_message_bytes(
                &channel_id,
                cumulative,
                self.expires_at.unwrap_or(0),
            )?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof(channel_id: &str) -> SessionAuthentication {
        SessionAuthentication::sign(
            "opening-challenge",
            channel_id,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )
        .unwrap()
    }

    #[test]
    fn exact_request_and_actions_round_trip() {
        let request: SessionRequest = serde_json::from_value(serde_json::json!({
            "amount": "25",
            "currency": "USDC",
            "recipient": "recipient",
            "minimumDeposit": "100",
            "suggestedDeposit": "1000",
            "unitType": "request",
            "methodDetails": {
                "network": "devnet",
                "channelProgram": "program",
                "voucherSigner": "operator",
                "operator": "operator",
                "distributionSplits": [{"recipient": "split", "shareBps": 250}],
                "idleTimeoutOptionsSeconds": [60, 300],
                "idleTimeoutSeconds": 300,
                "gracePeriodSeconds": 900
            }
        }))
        .unwrap();
        assert_eq!(request.amount, "25");
        assert_eq!(
            request.method_details.voucher_signer,
            Some(SessionVoucherSigner::Operator)
        );
        assert_eq!(request.method_details.distribution_splits[0].share_bps, 250);
        assert_eq!(
            serde_json::to_value(&request).unwrap()["methodDetails"]["channelProgram"],
            "program"
        );

        let channel = bs58::encode([3_u8; 32]).into_string();
        let authentication = proof(&channel);
        let open = OpenPayload::payment_channel(
            channel.clone(),
            "1000".into(),
            authentication.payer.clone(),
            "payee".into(),
            "mint".into(),
            42,
            900,
            99,
            "operator".into(),
            "wire".into(),
        )
        .with_authentication(authentication.clone())
        .with_idle_timeout(60);
        assert_eq!(open.session_id(), channel);
        assert_eq!(open.deposit_amount().unwrap(), 1000);
        assert!(OpenPayload {
            deposit_amount: "bad".into(),
            ..open.clone()
        }
        .deposit_amount()
        .is_err());

        let actions = [
            SessionAction::Open(open),
            SessionAction::Use(UsePayload {
                channel_id: channel.clone(),
                authentication: authentication.clone(),
            }),
            SessionAction::TopUp(TopUpPayload {
                channel_id: channel.clone(),
                additional_amount: "50".into(),
                transaction: "topup".into(),
            }),
            SessionAction::Close(ClosePayload {
                channel_id: channel.clone(),
                authentication: Some(authentication),
                voucher: None,
            }),
        ];
        for action in actions {
            let encoded = serde_json::to_string(&action).unwrap();
            let _: SessionAction = serde_json::from_str(&encoded).unwrap();
        }
    }

    #[test]
    fn open_payload_rejects_wire_bump() {
        let open = OpenPayload::payment_channel(
            "channel".to_string(),
            "100".to_string(),
            "payer".to_string(),
            "payee".to_string(),
            "mint".to_string(),
            7,
            900,
            42,
            "signer".to_string(),
            "transaction".to_string(),
        );
        let mut value = serde_json::to_value(open).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("bump".to_string(), serde_json::json!(255));
        let error = serde_json::from_value::<OpenPayload>(value).unwrap_err();
        assert!(error.to_string().contains("unknown field `bump`"));
    }

    #[test]
    fn authentication_is_bound_to_channel_and_validates_encoding() {
        let channel = bs58::encode([3_u8; 32]).into_string();
        let authentication = proof(&channel);
        assert!(authentication.verify(&channel).unwrap());
        assert!(!authentication
            .verify(&bs58::encode([4_u8; 32]).into_string())
            .unwrap());
        assert!(SessionAuthentication {
            payer: "bad".into(),
            ..authentication.clone()
        }
        .verify(&channel)
        .is_err());
        assert!(SessionAuthentication {
            signature: "bad".into(),
            ..authentication
        }
        .verify(&channel)
        .is_err());
    }

    #[test]
    fn timeout_policy_covers_valid_and_invalid_shapes() {
        assert!(validate_idle_timeout_options(&[]).is_err());
        assert!(validate_idle_timeout_options(&[0]).is_err());
        assert!(validate_idle_timeout_options(&[60, 60]).is_err());
        assert!(validate_idle_timeout_options(&[60, 300]).is_ok());
        assert_eq!(
            resolve_idle_timeout_seconds(300, Some(&[60, 300]), None).unwrap(),
            300
        );
        assert_eq!(
            resolve_idle_timeout_seconds(120, Some(&[60, 300]), None).unwrap(),
            60
        );
        assert_eq!(
            resolve_idle_timeout_seconds(300, Some(&[60, 300]), Some(60)).unwrap(),
            60
        );
        assert!(resolve_idle_timeout_seconds(0, None, None).is_err());
        assert!(resolve_idle_timeout_seconds(300, None, Some(60)).is_err());
        assert!(resolve_idle_timeout_seconds(300, Some(&[60, 300]), Some(120)).is_err());
    }

    #[test]
    fn voucher_and_metering_helpers_validate_decimal_strings() {
        let channel = bs58::encode([3_u8; 32]).into_string();
        let data = VoucherData {
            channel_id: channel,
            cumulative_amount: "25".into(),
            expires_at: None,
        };
        assert_eq!(data.message_bytes().unwrap().len(), 50);
        assert!(VoucherData {
            cumulative_amount: "bad".into(),
            ..data
        }
        .message_bytes()
        .is_err());
        let directive = MeteringDirective {
            delivery_id: "d1".into(),
            session_id: "c1".into(),
            amount: "25".into(),
            currency: "USDC".into(),
            sequence: 1,
            expires_at: DEFAULT_SESSION_EXPIRES_AT,
            commit_url: None,
            proof: None,
        };
        assert_eq!(directive.amount_base_units().unwrap(), 25);
        assert!(MeteringDirective {
            amount: "bad".into(),
            ..directive
        }
        .amount_base_units()
        .is_err());
        assert_eq!(
            MeteringUsage {
                delivery_id: "d1".into(),
                amount: "3".into()
            }
            .amount_base_units()
            .unwrap(),
            3
        );
        assert!(MeteringUsage {
            delivery_id: "d1".into(),
            amount: "bad".into()
        }
        .amount_base_units()
        .is_err());
    }

    #[test]
    fn voucher_action_and_receipt_use_exact_tags() {
        let voucher = SignedVoucher {
            data: VoucherData {
                channel_id: bs58::encode([3_u8; 32]).into_string(),
                cumulative_amount: "25".into(),
                expires_at: Some(100),
            },
            signer: bs58::encode([7_u8; 32]).into_string(),
            signature: bs58::encode([8_u8; 64]).into_string(),
            signature_type: VoucherSignatureType::Ed25519,
        };
        let value = serde_json::to_value(SessionAction::Voucher(VoucherPayload {
            channel_id: voucher.data.channel_id.clone(),
            voucher: voucher.clone(),
        }))
        .unwrap();
        assert_eq!(value["action"], "voucher");
        // Spec wire shape (mpp-specs e702dd8): top-level channelId routing
        // key next to the signed voucher, whose inner data field is named
        // `voucher` (not `data`).
        assert_eq!(value["channelId"], voucher.data.channel_id);
        assert_eq!(value["voucher"]["voucher"]["cumulativeAmount"], "25");
        assert!(value["voucher"].get("data").is_none());
        let commit = CommitPayload {
            delivery_id: "d1".into(),
            voucher,
        };
        assert_eq!(serde_json::to_value(commit).unwrap()["deliveryId"], "d1");
        assert_eq!(
            serde_json::to_value(CommitStatus::Committed).unwrap(),
            "committed"
        );
        assert_eq!(
            serde_json::to_value(CommitStatus::Replayed).unwrap(),
            "replayed"
        );
    }
}
