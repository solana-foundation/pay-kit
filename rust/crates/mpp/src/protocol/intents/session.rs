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

fn serialize_optional_u64_as_string<S>(
    value: &Option<u64>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_u64_from_string_or_number<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => value
            .parse::<u64>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("salt must be an unsigned 64-bit integer")),
        Some(_) => Err(serde::de::Error::custom(
            "salt must be a decimal string or unsigned 64-bit integer",
        )),
    }
}

/// On-chain funding mechanism for a session.
///
/// Advertised by the server in [`SessionRequest::modes`]; the client picks
/// the mode it will use when sending its [`SessionAction::Open`].
///
/// Naming mirrors the charge intent:
///
/// | Mode | Charge analogy | Who pays on-chain fees |
/// |------|---------------|------------------------|
/// | `push` | push (client broadcasts) | Client |
/// | `pull` | pull (server broadcasts) | Operator |
///
/// ## Push
/// Client opens a payment channel, locking funds as a deposit.
/// Client needs SOL (for fees) + the session token (e.g. USDC).
///
/// ## Pull
/// Pull only means the operator is involved in broadcasting or settling the
/// session. The concrete voucher authority is described by
/// [`SessionPullVoucherStrategy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionMode {
    /// Payment channel backed by an on-chain escrow deposit (client-funded).
    Push,
    /// Operator-assisted pull session. Voucher authority is declared separately.
    Pull,
}

/// Voucher authority used when [`SessionMode::Pull`] is advertised.
///
/// This intentionally separates "how the session is opened" from "who signs
/// spend vouchers":
///
/// - `clientVoucher`: the client signs cumulative vouchers. The operator may
///   use those vouchers as off-chain receipts without multi-delegate setup.
/// - `operatedVoucher`: the operator signs vouchers after metering/receipts and
///   uses multi-delegate setup for delegated token movement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionPullVoucherStrategy {
    /// Client-signed cumulative vouchers.
    ClientVoucher,
    /// Operator-signed vouchers.
    OperatedVoucher,
}

/// Session intent request — the payload embedded in a 402 challenge.
///
/// Describes the channel parameters: cap, currency, splits, network, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRequest {
    /// Maximum total amount the client may spend in this session (base units).
    pub cap: String,

    /// Currency/asset identifier (e.g., "USDC", mint address).
    pub currency: String,

    /// Token decimals (default 6 for USDC-like tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,

    /// Solana network: "mainnet-beta", "devnet", "localnet".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

    /// Operator (server) public key (base58).
    pub operator: String,

    /// Primary recipient for channel proceeds (base58).
    pub recipient: String,

    /// Optional splits: fixed portions routed to specific recipients at close.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub splits: Vec<SessionSplit>,

    /// Channel program ID (base58). Defaults to the canonical payment-channels program.
    #[serde(rename = "programId", skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Merchant reference ID.
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Minimum voucher increment (base units). Prevents micro-increment spam.
    #[serde(rename = "minVoucherDelta", skip_serializing_if = "Option::is_none")]
    pub min_voucher_delta: Option<String>,

    /// Session modes supported by this server.
    ///
    /// Omitted/empty means only [`SessionMode::Push`] is supported.
    /// The client MUST use one of the advertised modes in its `open` action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modes: Vec<SessionMode>,

    /// Voucher authority for pull-mode sessions.
    ///
    /// Required when `modes` includes [`SessionMode::Pull`]. Omitted when pull
    /// is not supported.
    #[serde(
        rename = "pullVoucherStrategy",
        skip_serializing_if = "Option::is_none"
    )]
    pub pull_voucher_strategy: Option<SessionPullVoucherStrategy>,

    /// Recent blockhash pre-fetched by the server (base58).
    ///
    /// Included when the client needs to build server-broadcast transactions
    /// without a second RPC round-trip. The client SHOULD use this when present
    /// rather than fetching its own.
    #[serde(rename = "recentBlockhash", skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,
}

/// A payment split committed at channel open; distributed to a specific
/// recipient when the channel closes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSplit {
    /// Recipient address (base58).
    pub recipient: String,

    /// Share in basis points.
    pub bps: u16,
}

// ── Client actions ──

/// The action submitted by the client in an Authorization header.
///
/// Serialized as a tagged object with `"action": "open" | "voucher" | "topup" | "close"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
pub enum SessionAction {
    /// Open a new channel/delegation and start the session.
    Open(OpenPayload),

    /// Submit a signed voucher authorizing payment for an API call.
    Voucher(VoucherPayload),

    /// Commit a metered delivery by attaching a signed voucher.
    Commit(CommitPayload),

    /// Top up an existing channel's deposit.
    TopUp(TopUpPayload),

    /// Request cooperative close of the channel.
    Close(ClosePayload),
}

/// Payload for the `open` action.
///
/// Use [`OpenPayload::push`], [`OpenPayload::payment_channel`], or
/// [`OpenPayload::pull`] to construct.
/// Inspect [`OpenPayload::mode`] to distinguish variants on the server.
///
/// Wire format:
/// ```json
/// // Payment-channel mode, client-broadcast push
/// {"action":"open","mode":"push","channelId":"...","deposit":"...","authorizedSigner":"...","signature":"..."}
///
/// // Payment-channel mode, server-broadcast pull
/// {"action":"open","mode":"pull","channelId":"...","deposit":"...","authorizedSigner":"...","transaction":"..."}
///
/// // Operated-voucher pull mode
/// {"action":"open","mode":"pull","tokenAccount":"...","approvedAmount":"...","authorizedSigner":"...","signature":"..."}
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenPayload {
    /// Session mode discriminant.
    pub mode: SessionMode,

    // ── Push mode ──────────────────────────────────────────────────────────
    /// Payment-channel address (base58). Required for `push` mode.
    #[serde(rename = "channelId", skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Deposit locked on-chain (base units). Required for `push` mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit: Option<String>,

    /// Client wallet that funds the payment channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,

    /// Primary channel payee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payee: Option<String>,

    /// SPL mint locked in the channel.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mint: Option<String>,

    /// Salt used in the channel PDA seeds.
    ///
    /// Serialized as a decimal string because authorization headers are JSON
    /// canonicalized, and arbitrary `u64` values are not safe JSON numbers.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_u64_from_string_or_number",
        serialize_with = "serialize_optional_u64_as_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub salt: Option<u64>,

    /// Grace period used by the on-chain close path.
    #[serde(rename = "gracePeriod", skip_serializing_if = "Option::is_none")]
    pub grace_period: Option<u32>,

    /// Signed payment-channel open transaction (base64), when the client wants
    /// the server/operator to broadcast it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,

    // ── Pull mode ──────────────────────────────────────────────────────────
    /// SPL token account being delegated (base58). Required for `pull` mode.
    #[serde(rename = "tokenAccount", skip_serializing_if = "Option::is_none")]
    pub token_account: Option<String>,

    /// Amount approved for operator delegation (base units). Required for `pull` mode.
    #[serde(rename = "approvedAmount", skip_serializing_if = "Option::is_none")]
    pub approved_amount: Option<String>,

    /// Client wallet pubkey (base58). Required for `pull` mode.
    ///
    /// The operator uses this to derive the MultiDelegate PDA and build the
    /// `TransferFixed` instruction data at settlement time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,

    /// Pre-signed transaction (base64) that creates the `MultiDelegate` PDA
    /// and an initial `FixedDelegation`.
    ///
    /// The client should always include this for pull-mode opens. The server
    /// submits it only if the `MultiDelegate` PDA does not yet exist on-chain.
    #[serde(
        rename = "initMultiDelegateTx",
        skip_serializing_if = "Option::is_none"
    )]
    pub init_multi_delegate_tx: Option<String>,

    /// Pre-signed transaction (base64) that creates or raises the
    /// `FixedDelegation` cap.
    ///
    /// The client should always include this for pull-mode opens. The server
    /// submits it only if the existing delegation cap is below the session cap.
    #[serde(rename = "updateDelegationTx", skip_serializing_if = "Option::is_none")]
    pub update_delegation_tx: Option<String>,

    // ── Shared ─────────────────────────────────────────────────────────────
    /// The public key authorized to sign vouchers for this session (base58).
    /// Usually an ephemeral key generated by the client.
    #[serde(rename = "authorizedSigner")]
    pub authorized_signer: String,

    /// Transaction signature (base58) proving the on-chain action.
    ///
    /// - Payment-channel push: client-broadcast open transaction signature.
    /// - Payment-channel pull: server-broadcast open transaction signature, filled
    ///   by the server after submission.
    /// - Operated-voucher pull: delegation setup transaction signature.
    pub signature: String,
}

impl OpenPayload {
    /// Construct a **push** payment-channel open payload.
    pub fn push(
        channel_id: String,
        deposit: String,
        authorized_signer: String,
        signature: String,
    ) -> Self {
        Self {
            mode: SessionMode::Push,
            channel_id: Some(channel_id),
            deposit: Some(deposit),
            payer: None,
            payee: None,
            mint: None,
            salt: None,
            grace_period: None,
            transaction: None,
            token_account: None,
            approved_amount: None,
            owner: None,
            init_multi_delegate_tx: None,
            update_delegation_tx: None,
            authorized_signer,
            signature,
        }
    }

    /// Construct a payment-channel **push** open payload.
    #[allow(clippy::too_many_arguments)]
    pub fn payment_channel(
        channel_id: String,
        deposit: String,
        payer: String,
        payee: String,
        mint: String,
        salt: u64,
        grace_period: u32,
        authorized_signer: String,
        signature: String,
    ) -> Self {
        Self::payment_channel_with_mode(
            SessionMode::Push,
            channel_id,
            deposit,
            payer,
            payee,
            mint,
            salt,
            grace_period,
            authorized_signer,
            signature,
        )
    }

    /// Construct a payment-channel open payload with an explicit submission mode.
    #[allow(clippy::too_many_arguments)]
    pub fn payment_channel_with_mode(
        mode: SessionMode,
        channel_id: String,
        deposit: String,
        payer: String,
        payee: String,
        mint: String,
        salt: u64,
        grace_period: u32,
        authorized_signer: String,
        signature: String,
    ) -> Self {
        Self {
            mode,
            channel_id: Some(channel_id),
            deposit: Some(deposit),
            payer: Some(payer),
            payee: Some(payee),
            mint: Some(mint),
            salt: Some(salt),
            grace_period: Some(grace_period),
            transaction: None,
            token_account: None,
            approved_amount: None,
            owner: None,
            init_multi_delegate_tx: None,
            update_delegation_tx: None,
            authorized_signer,
            signature,
        }
    }

    /// Attach a signed open transaction for operator/server broadcast.
    pub fn with_transaction(mut self, tx_base64: String) -> Self {
        self.transaction = Some(tx_base64);
        self
    }

    /// Construct a **pull** (SPL delegation) open payload.
    pub fn pull(
        token_account: String,
        approved_amount: String,
        owner: String,
        authorized_signer: String,
        signature: String,
    ) -> Self {
        Self {
            mode: SessionMode::Pull,
            channel_id: None,
            deposit: None,
            payer: None,
            payee: None,
            mint: None,
            salt: None,
            grace_period: None,
            transaction: None,
            token_account: Some(token_account),
            approved_amount: Some(approved_amount),
            owner: Some(owner),
            init_multi_delegate_tx: None,
            update_delegation_tx: None,
            authorized_signer,
            signature,
        }
    }

    /// Attach a pre-signed `InitMultiDelegate` + `CreateFixedDelegation`
    /// transaction.  The server submits this if the `MultiDelegate` PDA does
    /// not yet exist on-chain.
    pub fn with_init_tx(mut self, tx_base64: String) -> Self {
        self.init_multi_delegate_tx = Some(tx_base64);
        self
    }

    /// Attach a pre-signed `CreateFixedDelegation` (cap update) transaction.
    /// The server submits this if the existing delegation cap is below the
    /// session amount.
    pub fn with_update_tx(mut self, tx_base64: String) -> Self {
        self.update_delegation_tx = Some(tx_base64);
        self
    }

    /// Session identifier used as the store key.
    ///
    /// - Payment channel: `channel_id`
    /// - Operated-voucher pull: `token_account`
    pub fn session_id(&self) -> crate::error::Result<&str> {
        if let Some(channel_id) = self.channel_id.as_deref() {
            return Ok(channel_id);
        }

        match self.mode {
            SessionMode::Push => Err(crate::error::Error::Other(
                "push open missing channelId".to_string(),
            )),
            SessionMode::Pull => self.token_account.as_deref().ok_or_else(|| {
                crate::error::Error::Other(
                    "pull open missing channelId or tokenAccount".to_string(),
                )
            }),
        }
    }

    /// Deposit / approved amount for this open (base units).
    pub fn deposit_amount(&self) -> crate::error::Result<u64> {
        let raw = if let Some(deposit) = self.deposit.as_deref() {
            deposit
        } else {
            match self.mode {
                SessionMode::Push => {
                    return Err(crate::error::Error::Other(
                        "push open missing deposit".to_string(),
                    ));
                }
                SessionMode::Pull => self.approved_amount.as_deref().ok_or_else(|| {
                    crate::error::Error::Other(
                        "pull open missing deposit or approvedAmount".to_string(),
                    )
                })?,
            }
        };
        raw.parse()
            .map_err(|_| crate::error::Error::Other(format!("invalid deposit amount: {raw}")))
    }
}

/// Payload for the `voucher` action (per-request micropayment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherPayload {
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
    pub fn amount_base_units(&self) -> crate::error::Result<u64> {
        self.amount.parse().map_err(|_| {
            crate::error::Error::Other(format!("invalid metering amount: {}", self.amount))
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
    pub fn amount_base_units(&self) -> crate::error::Result<u64> {
        self.amount.parse().map_err(|_| {
            crate::error::Error::Other(format!("invalid metering usage amount: {}", self.amount))
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

/// Payload for the `topup` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopUpPayload {
    /// The on-chain channel address (base58).
    #[serde(rename = "channelId")]
    pub channel_id: String,

    /// New total deposit amount after the top-up (base units).
    #[serde(rename = "newDeposit")]
    pub new_deposit: String,

    /// The top-up transaction signature (base58).
    pub signature: String,
}

/// Payload for the `close` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePayload {
    /// The on-chain channel address (base58).
    #[serde(rename = "channelId")]
    pub channel_id: String,

    /// Final signed voucher for any remaining balance owed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher: Option<SignedVoucher>,
}

// ── Vouchers ──

/// A signed voucher authorizing cumulative payment up to `cumulative`.
///
/// Vouchers are **cumulative**: the server always uses the latest valid voucher
/// it has received. The client MUST increment `cumulative` with each request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVoucher {
    /// The voucher content.
    pub data: VoucherData,

    /// Ed25519 signature over the payment-channel Borsh voucher bytes (base58).
    pub signature: String,
}

/// The canonical content of a voucher, signed by the client's session key.
///
/// Serialized as the on-chain `VoucherArgs` layout before signing:
/// `channel_id || cumulative_amount_le || expires_at_le`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherData {
    /// The channel/session ID this voucher is bound to (base58).
    ///
    /// For push sessions: the payment-channel address.
    /// For pull sessions: the SPL token account address.
    #[serde(rename = "channelId")]
    pub channel_id: String,

    /// Cumulative amount authorized (base units, monotonically increasing).
    #[serde(rename = "cumulativeAmount", alias = "cumulative")]
    pub cumulative: String,

    /// Unix timestamp at which this voucher expires.
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,

    /// Optional client-side request counter. It is not included in the
    /// on-chain voucher bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
}

impl VoucherData {
    /// Serialize to the payment-channels `VoucherArgs` bytes signed by Ed25519.
    pub fn message_bytes(&self) -> crate::error::Result<Vec<u8>> {
        let channel_id = crate::program::payment_channels::parse_pubkey(&self.channel_id)?;
        let cumulative = self
            .cumulative
            .parse()
            .map_err(|_| crate::error::Error::Other("invalid voucher cumulative".to_string()))?;
        crate::program::payment_channels::voucher_message_bytes(
            &channel_id,
            cumulative,
            self.expires_at,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SessionMode ───────────────────────────────────────────────────────────

    #[test]
    fn session_mode_push_serializes_as_push() {
        let json = serde_json::to_string(&SessionMode::Push).unwrap();
        assert_eq!(json, r#""push""#);
    }

    #[test]
    fn session_mode_pull_serializes_as_pull() {
        let json = serde_json::to_string(&SessionMode::Pull).unwrap();
        assert_eq!(json, r#""pull""#);
    }

    #[test]
    fn session_mode_roundtrip() {
        for mode in [SessionMode::Push, SessionMode::Pull] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: SessionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn session_pull_voucher_strategy_roundtrip() {
        let json = serde_json::to_string(&SessionPullVoucherStrategy::ClientVoucher).unwrap();
        assert_eq!(json, r#""clientVoucher""#);
        let back: SessionPullVoucherStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SessionPullVoucherStrategy::ClientVoucher);

        let json = serde_json::to_string(&SessionPullVoucherStrategy::OperatedVoucher).unwrap();
        assert_eq!(json, r#""operatedVoucher""#);
        let back: SessionPullVoucherStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, SessionPullVoucherStrategy::OperatedVoucher);
    }

    // ── SessionRequest ────────────────────────────────────────────────────────

    #[test]
    fn session_request_roundtrip() {
        let req = SessionRequest {
            cap: "10000000".to_string(),
            currency: "USDC".to_string(),
            decimals: Some(6),
            network: Some("mainnet-beta".to_string()),
            operator: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            splits: vec![],
            program_id: None,
            description: Some("API session".to_string()),
            external_id: None,
            min_voucher_delta: None,
            modes: vec![SessionMode::Push],
            pull_voucher_strategy: None,
            recent_blockhash: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cap, "10000000");
        assert_eq!(back.currency, "USDC");
        assert_eq!(back.description.as_deref(), Some("API session"));
        assert_eq!(back.modes, vec![SessionMode::Push]);
    }

    #[test]
    fn session_request_omits_empty_splits_and_modes() {
        let req = SessionRequest {
            cap: "1000".to_string(),
            currency: "USDC".to_string(),
            decimals: None,
            network: None,
            operator: "op".to_string(),
            recipient: "rec".to_string(),
            splits: vec![],
            program_id: None,
            description: None,
            external_id: None,
            min_voucher_delta: None,
            modes: vec![],
            pull_voucher_strategy: None,
            recent_blockhash: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("splits"));
        assert!(!json.contains("modes"));
        assert!(!json.contains("decimals"));
        assert!(!json.contains("network"));
        assert!(!json.contains("description"));
        assert!(!json.contains("externalId"));
    }

    #[test]
    fn session_request_with_modes_push_and_pull() {
        let req = SessionRequest {
            cap: "1000".to_string(),
            currency: "USDC".to_string(),
            decimals: None,
            network: None,
            operator: "op".to_string(),
            recipient: "rec".to_string(),
            splits: vec![],
            program_id: None,
            description: None,
            external_id: None,
            min_voucher_delta: None,
            modes: vec![SessionMode::Push, SessionMode::Pull],
            pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
            recent_blockhash: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"push\""));
        assert!(json.contains("\"pull\""));
        assert!(json.contains("\"pullVoucherStrategy\":\"clientVoucher\""));
        let back: SessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.modes.len(), 2);
        assert_eq!(back.modes[0], SessionMode::Push);
        assert_eq!(back.modes[1], SessionMode::Pull);
        assert_eq!(
            back.pull_voucher_strategy,
            Some(SessionPullVoucherStrategy::ClientVoucher)
        );
    }

    #[test]
    fn session_request_with_splits() {
        let req = SessionRequest {
            cap: "1000".to_string(),
            currency: "USDC".to_string(),
            decimals: None,
            network: None,
            operator: "op".to_string(),
            recipient: "rec".to_string(),
            splits: vec![
                SessionSplit {
                    recipient: "s1".to_string(),
                    bps: 100,
                },
                SessionSplit {
                    recipient: "s2".to_string(),
                    bps: 200,
                },
            ],
            program_id: Some("prog123".to_string()),
            description: None,
            external_id: Some("ref-1".to_string()),
            min_voucher_delta: None,
            modes: vec![],
            pull_voucher_strategy: None,
            recent_blockhash: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.splits.len(), 2);
        assert_eq!(back.splits[0].bps, 100);
        assert_eq!(back.program_id.as_deref(), Some("prog123"));
        assert_eq!(back.external_id.as_deref(), Some("ref-1"));
    }

    // ── OpenPayload constructors ──────────────────────────────────────────────

    #[test]
    fn open_payload_push_fields() {
        let p = OpenPayload::push(
            "chan1".to_string(),
            "1000000".to_string(),
            "signer1".to_string(),
            "txsig".to_string(),
        );
        assert_eq!(p.mode, SessionMode::Push);
        assert_eq!(p.channel_id.as_deref(), Some("chan1"));
        assert_eq!(p.deposit.as_deref(), Some("1000000"));
        assert!(p.token_account.is_none());
        assert!(p.approved_amount.is_none());
        assert_eq!(p.authorized_signer, "signer1");
        assert_eq!(p.signature, "txsig");
    }

    #[test]
    fn open_payload_pull_fields() {
        let p = OpenPayload::pull(
            "tokacct".to_string(),
            "5000000".to_string(),
            "wallet1".to_string(),
            "signer1".to_string(),
            "approvesig".to_string(),
        );
        assert_eq!(p.mode, SessionMode::Pull);
        assert!(p.channel_id.is_none());
        assert!(p.deposit.is_none());
        assert_eq!(p.token_account.as_deref(), Some("tokacct"));
        assert_eq!(p.approved_amount.as_deref(), Some("5000000"));
        assert_eq!(p.owner.as_deref(), Some("wallet1"));
    }

    #[test]
    fn open_payload_payment_channel_and_tx_helpers() {
        let p = OpenPayload::payment_channel(
            "chan1".to_string(),
            "1000000".to_string(),
            "payer1".to_string(),
            "payee1".to_string(),
            "mint1".to_string(),
            99,
            45,
            "signer1".to_string(),
            "txsig".to_string(),
        )
        .with_transaction("open-tx".to_string())
        .with_init_tx("init-tx".to_string())
        .with_update_tx("update-tx".to_string());

        assert_eq!(p.mode, SessionMode::Push);
        assert_eq!(p.session_id().unwrap(), "chan1");
        assert_eq!(p.deposit_amount().unwrap(), 1_000_000);
        assert_eq!(p.payer.as_deref(), Some("payer1"));
        assert_eq!(p.payee.as_deref(), Some("payee1"));
        assert_eq!(p.mint.as_deref(), Some("mint1"));
        assert_eq!(p.salt, Some(99));
        assert_eq!(p.grace_period, Some(45));
        assert_eq!(p.transaction.as_deref(), Some("open-tx"));
        assert_eq!(p.init_multi_delegate_tx.as_deref(), Some("init-tx"));
        assert_eq!(p.update_delegation_tx.as_deref(), Some("update-tx"));
    }

    #[test]
    fn open_payload_pull_payment_channel_uses_channel_id_and_deposit() {
        let p = OpenPayload::payment_channel_with_mode(
            SessionMode::Pull,
            "chan1".to_string(),
            "1000000".to_string(),
            "payer1".to_string(),
            "payee1".to_string(),
            "mint1".to_string(),
            99,
            45,
            "signer1".to_string(),
            "pending".to_string(),
        )
        .with_transaction("open-tx".to_string());

        assert_eq!(p.mode, SessionMode::Pull);
        assert_eq!(p.session_id().unwrap(), "chan1");
        assert_eq!(p.deposit_amount().unwrap(), 1_000_000);
        assert_eq!(p.channel_id.as_deref(), Some("chan1"));
        assert_eq!(p.deposit.as_deref(), Some("1000000"));
        assert!(p.token_account.is_none());
        assert!(p.approved_amount.is_none());
        assert_eq!(p.transaction.as_deref(), Some("open-tx"));
    }

    #[test]
    fn open_payload_push_session_id_and_deposit() {
        let p = OpenPayload::push(
            "chan1".to_string(),
            "2000000".to_string(),
            "s".to_string(),
            "sig".to_string(),
        );
        assert_eq!(p.session_id().unwrap(), "chan1");
        assert_eq!(p.deposit_amount().unwrap(), 2_000_000);
    }

    #[test]
    fn open_payload_pull_session_id_and_deposit() {
        let p = OpenPayload::pull(
            "tokacct".to_string(),
            "3000000".to_string(),
            "wallet1".to_string(),
            "s".to_string(),
            "sig".to_string(),
        );
        assert_eq!(p.session_id().unwrap(), "tokacct");
        assert_eq!(p.deposit_amount().unwrap(), 3_000_000);
    }

    #[test]
    fn open_payload_missing_required_fields_and_invalid_deposit_error() {
        let mut push = OpenPayload::push(
            "chan1".to_string(),
            "bad".to_string(),
            "s".to_string(),
            "sig".to_string(),
        );
        assert!(push.deposit_amount().is_err());
        push.deposit = None;
        assert!(push.deposit_amount().is_err());
        push.channel_id = None;
        assert!(push.session_id().is_err());

        let mut pull = OpenPayload::pull(
            "tokacct".to_string(),
            "bad".to_string(),
            "wallet".to_string(),
            "s".to_string(),
            "sig".to_string(),
        );
        assert!(pull.deposit_amount().is_err());
        pull.approved_amount = None;
        assert!(pull.deposit_amount().is_err());
        pull.token_account = None;
        assert!(pull.session_id().is_err());
    }

    #[test]
    fn open_payload_push_roundtrip_json() {
        let p = OpenPayload::push(
            "chan1".to_string(),
            "1000000".to_string(),
            "signer1".to_string(),
            "txsig".to_string(),
        );
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""mode":"push""#));
        assert!(json.contains(r#""channelId":"chan1""#));
        assert!(!json.contains("tokenAccount"));
        let back: OpenPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, SessionMode::Push);
        assert_eq!(back.channel_id.as_deref(), Some("chan1"));
    }

    #[test]
    fn open_payload_pull_roundtrip_json() {
        let p = OpenPayload::pull(
            "tokacct".to_string(),
            "5000000".to_string(),
            "wallet1".to_string(),
            "signer1".to_string(),
            "approvesig".to_string(),
        );
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(r#""mode":"pull""#));
        assert!(json.contains(r#""tokenAccount":"tokacct""#));
        assert!(json.contains(r#""owner":"wallet1""#));
        assert!(!json.contains("channelId"));
        let back: OpenPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, SessionMode::Pull);
        assert_eq!(back.token_account.as_deref(), Some("tokacct"));
        assert_eq!(back.owner.as_deref(), Some("wallet1"));
    }

    #[test]
    fn payment_channel_salt_serializes_as_string_and_accepts_legacy_number() {
        let salt = u64::MAX - 7;
        let p = OpenPayload::payment_channel(
            "chan1".to_string(),
            "1000000".to_string(),
            "payer1".to_string(),
            "payee1".to_string(),
            "mint1".to_string(),
            salt,
            900,
            "signer1".to_string(),
            "txsig".to_string(),
        );

        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains(&format!(r#""salt":"{salt}""#)));
        let back: OpenPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.salt, Some(salt));

        let legacy_json = format!(
            r#"{{"mode":"push","channelId":"chan1","deposit":"1000000","payer":"payer1","payee":"payee1","mint":"mint1","salt":42,"gracePeriod":900,"authorizedSigner":"signer1","signature":"txsig"}}"#
        );
        let legacy: OpenPayload = serde_json::from_str(&legacy_json).unwrap();
        assert_eq!(legacy.salt, Some(42));
    }

    #[test]
    fn open_payload_missing_mode_fails_deserialization() {
        // Clients must always send "mode" — no default.
        let json =
            r#"{"channelId":"chan1","deposit":"1000","authorizedSigner":"s","signature":"sig"}"#;
        assert!(serde_json::from_str::<OpenPayload>(json).is_err());
    }

    #[test]
    fn metering_amount_parsers_and_usage_roundtrip() {
        let directive = MeteringDirective {
            delivery_id: "d1".to_string(),
            session_id: "chan1".to_string(),
            amount: "not-a-number".to_string(),
            currency: "USDC".to_string(),
            sequence: 1,
            expires_at: DEFAULT_SESSION_EXPIRES_AT,
            commit_url: None,
            proof: Some("proof".to_string()),
        };
        assert!(directive.amount_base_units().is_err());

        let usage = MeteringUsage {
            delivery_id: "d1".to_string(),
            amount: "42".to_string(),
        };
        let json = serde_json::to_string(&usage).unwrap();
        assert!(json.contains(r#""deliveryId":"d1""#));
        let back: MeteringUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.amount_base_units().unwrap(), 42);

        let bad_usage = MeteringUsage {
            delivery_id: "d1".to_string(),
            amount: "bad".to_string(),
        };
        assert!(bad_usage.amount_base_units().is_err());
    }

    // ── SessionAction variants ────────────────────────────────────────────────

    #[test]
    fn session_action_open_push_roundtrip() {
        let action = SessionAction::Open(OpenPayload::push(
            "chan123".to_string(),
            "5000000".to_string(),
            "signer123".to_string(),
            "sig456".to_string(),
        ));
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"open""#));
        assert!(json.contains(r#""mode":"push""#));
        let back: SessionAction = serde_json::from_str(&json).unwrap();
        match back {
            SessionAction::Open(p) => {
                assert_eq!(p.mode, SessionMode::Push);
                assert_eq!(p.session_id().unwrap(), "chan123");
                assert_eq!(p.deposit_amount().unwrap(), 5_000_000);
                assert_eq!(p.authorized_signer, "signer123");
            }
            _ => panic!("Expected Open"),
        }
    }

    #[test]
    fn session_action_open_pull_roundtrip() {
        let action = SessionAction::Open(OpenPayload::pull(
            "tokacct".to_string(),
            "3000000".to_string(),
            "wallet1".to_string(),
            "signer1".to_string(),
            "approvesig".to_string(),
        ));
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"open""#));
        assert!(json.contains(r#""mode":"pull""#));
        assert!(json.contains("tokenAccount"));
        let back: SessionAction = serde_json::from_str(&json).unwrap();
        match back {
            SessionAction::Open(p) => {
                assert_eq!(p.mode, SessionMode::Pull);
                assert_eq!(p.session_id().unwrap(), "tokacct");
                assert_eq!(p.deposit_amount().unwrap(), 3_000_000);
            }
            _ => panic!("Expected Open"),
        }
    }

    #[test]
    fn session_action_voucher_roundtrip() {
        let action = SessionAction::Voucher(VoucherPayload {
            voucher: SignedVoucher {
                data: VoucherData {
                    channel_id: "chan1".to_string(),
                    cumulative: "500000".to_string(),
                    expires_at: i64::MAX,
                    nonce: Some(3),
                },
                signature: "sig_here".to_string(),
            },
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"voucher""#));
        let back: SessionAction = serde_json::from_str(&json).unwrap();
        match back {
            SessionAction::Voucher(p) => {
                assert_eq!(p.voucher.data.cumulative, "500000");
                assert_eq!(p.voucher.data.nonce, Some(3));
            }
            _ => panic!("Expected Voucher"),
        }
    }

    #[test]
    fn session_action_commit_roundtrip() {
        let action = SessionAction::Commit(CommitPayload {
            delivery_id: "delivery-1".to_string(),
            voucher: SignedVoucher {
                data: VoucherData {
                    channel_id: "chan1".to_string(),
                    cumulative: "500000".to_string(),
                    expires_at: i64::MAX,
                    nonce: Some(3),
                },
                signature: "sig_here".to_string(),
            },
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"commit""#));
        assert!(json.contains(r#""deliveryId":"delivery-1""#));
        let back: SessionAction = serde_json::from_str(&json).unwrap();
        match back {
            SessionAction::Commit(p) => {
                assert_eq!(p.delivery_id, "delivery-1");
                assert_eq!(p.voucher.data.cumulative, "500000");
            }
            _ => panic!("Expected Commit"),
        }
    }

    #[test]
    fn metering_directive_and_envelope_roundtrip() {
        let directive = MeteringDirective {
            delivery_id: "d1".to_string(),
            session_id: "chan1".to_string(),
            amount: "125".to_string(),
            currency: "USDC".to_string(),
            sequence: 7,
            expires_at: 4_102_444_800,
            commit_url: Some("https://example.test/commit".to_string()),
            proof: None,
        };
        assert_eq!(directive.amount_base_units().unwrap(), 125);

        let envelope = MeteredEnvelope {
            payload: serde_json::json!({"ok": true}),
            metering: directive,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains(r#""deliveryId":"d1""#));
        assert!(json.contains(r#""commitUrl":"https://example.test/commit""#));

        let back: MeteredEnvelope<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.metering.sequence, 7);
        assert_eq!(back.payload["ok"], true);
    }

    #[test]
    fn session_action_topup_roundtrip() {
        let action = SessionAction::TopUp(TopUpPayload {
            channel_id: "chan1".to_string(),
            new_deposit: "9000000".to_string(),
            signature: "txsig".to_string(),
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"topUp""#));
        let back: SessionAction = serde_json::from_str(&json).unwrap();
        match back {
            SessionAction::TopUp(p) => {
                assert_eq!(p.new_deposit, "9000000");
                assert_eq!(p.signature, "txsig");
            }
            _ => panic!("Expected TopUp"),
        }
    }

    #[test]
    fn session_action_close_no_voucher_roundtrip() {
        let action = SessionAction::Close(ClosePayload {
            channel_id: "chan1".to_string(),
            voucher: None,
        });
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains(r#""action":"close""#));
        assert!(!json.contains("voucher"));
        let back: SessionAction = serde_json::from_str(&json).unwrap();
        match back {
            SessionAction::Close(p) => assert!(p.voucher.is_none()),
            _ => panic!("Expected Close"),
        }
    }

    #[test]
    fn session_action_close_with_voucher_roundtrip() {
        let action = SessionAction::Close(ClosePayload {
            channel_id: "chan1".to_string(),
            voucher: Some(SignedVoucher {
                data: VoucherData {
                    channel_id: "chan1".to_string(),
                    cumulative: "700000".to_string(),
                    expires_at: i64::MAX,
                    nonce: Some(7),
                },
                signature: "final_sig".to_string(),
            }),
        });
        let json = serde_json::to_string(&action).unwrap();
        let back: SessionAction = serde_json::from_str(&json).unwrap();
        match back {
            SessionAction::Close(p) => {
                let v = p.voucher.unwrap();
                assert_eq!(v.data.cumulative, "700000");
            }
            _ => panic!("Expected Close"),
        }
    }

    // ── VoucherData ───────────────────────────────────────────────────────────

    #[test]
    fn voucher_data_message_bytes_with_nonce() {
        let channel_id = bs58::encode([3u8; 32]).into_string();
        let data = VoucherData {
            channel_id: channel_id.clone(),
            cumulative: "1000".to_string(),
            expires_at: 42,
            nonce: Some(1),
        };
        let bytes = data.message_bytes().unwrap();
        assert_eq!(bytes.len(), 48);
        assert_eq!(&bytes[..32], bs58::decode(channel_id).into_vec().unwrap());
        assert_eq!(&bytes[32..40], &1000u64.to_le_bytes());
        assert_eq!(&bytes[40..48], &42i64.to_le_bytes());
    }

    #[test]
    fn voucher_data_message_bytes_without_nonce() {
        let data = VoucherData {
            channel_id: bs58::encode([4u8; 32]).into_string(),
            cumulative: "1000".to_string(),
            expires_at: 42,
            nonce: None,
        };
        let bytes = data.message_bytes().unwrap();
        assert_eq!(bytes.len(), 48);
    }

    #[test]
    fn voucher_data_message_bytes_deterministic() {
        let data = VoucherData {
            channel_id: bs58::encode([5u8; 32]).into_string(),
            cumulative: "1000".to_string(),
            expires_at: 42,
            nonce: Some(5),
        };
        assert_eq!(data.message_bytes().unwrap(), data.message_bytes().unwrap());
    }

    #[test]
    fn voucher_data_message_bytes_differs_by_cumulative() {
        let channel_id = bs58::encode([6u8; 32]).into_string();
        let a = VoucherData {
            channel_id: channel_id.clone(),
            cumulative: "100".to_string(),
            expires_at: 42,
            nonce: None,
        };
        let b = VoucherData {
            channel_id,
            cumulative: "200".to_string(),
            expires_at: 42,
            nonce: None,
        };
        assert_ne!(a.message_bytes().unwrap(), b.message_bytes().unwrap());
    }

    #[test]
    fn signed_voucher_fields() {
        let v = SignedVoucher {
            data: VoucherData {
                channel_id: "c".to_string(),
                cumulative: "100".to_string(),
                expires_at: i64::MAX,
                nonce: None,
            },
            signature: "abc123".to_string(),
        };
        assert_eq!(v.data.cumulative, "100");
        assert_eq!(v.signature, "abc123");
    }

    // ── Pricing fields ────────────────────────────────────────────────────────

    #[test]
    fn session_request_with_min_voucher_delta() {
        let req = SessionRequest {
            cap: "10000000".to_string(),
            currency: "USDC".to_string(),
            decimals: Some(6),
            network: Some("mainnet-beta".to_string()),
            operator: "op".to_string(),
            recipient: "rec".to_string(),
            splits: vec![],
            program_id: None,
            description: None,
            external_id: None,
            min_voucher_delta: Some("500".to_string()),
            modes: vec![],
            pull_voucher_strategy: None,
            recent_blockhash: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: SessionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_voucher_delta.as_deref(), Some("500"));
        assert!(json.contains("\"minVoucherDelta\""));
    }

    #[test]
    fn session_request_omits_min_voucher_delta_when_none() {
        let req = SessionRequest {
            cap: "1000".to_string(),
            currency: "USDC".to_string(),
            decimals: None,
            network: None,
            operator: "op".to_string(),
            recipient: "rec".to_string(),
            splits: vec![],
            program_id: None,
            description: None,
            external_id: None,
            min_voucher_delta: None,
            modes: vec![],
            pull_voucher_strategy: None,
            recent_blockhash: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("minVoucherDelta"));
    }
}
