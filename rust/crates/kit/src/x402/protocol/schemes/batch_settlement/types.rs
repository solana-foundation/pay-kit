//! Wire types for the SVM `batch-settlement` scheme.
//!
//! High-throughput channel payments: the client deposits once into an escrow
//! channel, then signs cumulative Ed25519 vouchers per request. The server
//! verifies each voucher offchain, stores the latest commitment, serves
//! immediately, and redeems the latest voucher onchain later, in batches.
//!
//! The onchain backing is the payment-channels program and its 50-byte voucher,
//! shared with SVM `upto`; the channel / voucher / store logic is the
//! wire-agnostic core in [`crate::core`], also used by the MPP `session` intent.
//!
//! Field names, casing, and encodings here are normative — they are the bytes
//! on the wire, and they match the TypeScript implementation exactly. See
//! `specs/schemes/batch-settlement/scheme_batch_settlement_svm.md` §4.

use serde::{Deserialize, Serialize};

use crate::x402::error::Error;
use crate::x402::protocol::schemes::exact::ResourceInfo;

/// `batch-settlement` scheme identifier.
pub const BATCH_SETTLEMENT_SCHEME: &str = "batch-settlement";

/// The only payment flow this scheme resolves to. Read-only verification runs
/// before the resource handler; `/settle` commits the voucher — and broadcasts
/// any `deposit` transaction — after it.
pub const PAYMENT_FLOW_AUTHORIZATION: &str = "authorization";

/// Minimum forced-close grace period (15 minutes). An x402 conformance bound:
/// the program itself accepts any positive `grace_period`.
pub const MIN_WITHDRAW_DELAY_SECONDS: u32 = 900;

/// Maximum forced-close grace period (30 days).
pub const MAX_WITHDRAW_DELAY_SECONDS: u32 = 2_592_000;

/// Maximum voucher claims in one `claim` batch, so the Ed25519-precompile plus
/// `settle` instruction pairs fit a legacy transaction without lookup tables.
pub const MAX_CLAIMS_PER_BATCH: usize = 4;

/// The only voucher expiry this scheme permits.
///
/// The forced-close grace period after a payer `request_close` already bounds
/// the redemption window. A per-voucher expiry would add a second clock the
/// server has to beat, and could make an accepted voucher unredeemable while
/// the channel is still open — after the resource was already served.
pub const VOUCHER_EXPIRES_AT: i64 = 0;

fn batch_scheme() -> String {
    BATCH_SETTLEMENT_SCHEME.to_string()
}

/// Parse an atomic-unit amount carried on the wire as a decimal string.
fn parse_amount(value: &str, field: &str) -> Result<u64, Error> {
    value
        .parse()
        .map_err(|_| Error::Other(format!("invalid {field}: {value:?}")))
}

// ── PaymentRequirements (in `PAYMENT-REQUIRED.accepts[]`) ──

/// The `extra` object on a `batch-settlement` requirement.
///
/// Note what is deliberately absent: the payment-channels program id. It is a
/// network/SDK constant, never a server-provided wire field — an implementation
/// that negotiated it from `extra` would let a resource server point the client
/// at a program of its choosing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchExtra {
    /// When present, MUST be `"authorization"`. Normally omitted, since the
    /// scheme resolves to that protocol default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_flow: Option<String>,

    /// Base58 sponsor key, recorded by the program as both `Channel.rent_payer`
    /// and the zero-share `Channel.payee`. Co-signs setup transactions as the
    /// transaction fee payer and signs channel lifecycle transactions.
    pub fee_payer: String,

    /// Base58 server-controlled key that authenticates an optional immediate
    /// cooperative close to the facilitator. Not a payment-channel account
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_authorizer: Option<String>,

    /// Forced-close grace period in seconds, encoded exactly as the program
    /// `grace_period`. Must be in
    /// [`MIN_WITHDRAW_DELAY_SECONDS`]`..=`[`MAX_WITHDRAW_DELAY_SECONDS`] and at
    /// least `maxTimeoutSeconds`.
    pub withdraw_delay: u32,

    /// SPL Token or Token-2022 program that owns `asset`. The client and
    /// sponsor MUST verify it against the onchain mint owner rather than trust
    /// this value.
    pub token_program: String,

    /// Seller-defined UTF-8 payment reference for the setup transaction's Memo
    /// instruction. At most 256 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,

    /// Pre-fetched blockhash the client MAY use to build `open` / `top_up`
    /// without an RPC round trip. A construction hint only: it is not channel
    /// configuration and is not part of the signed voucher.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_blockhash: Option<String>,

    /// Recent slot the client MAY use as `channelConfig.openSlot`. A hint only;
    /// the program still enforces its own open-slot window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_slot: Option<u64>,

    /// Corrective-only server channel snapshot, for cumulative-amount
    /// resynchronization. See [`BatchRequirements::is_corrective`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_state: Option<ChannelStateSnapshot>,

    /// Corrective-only signed voucher proof, for cumulative-amount
    /// resynchronization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_state: Option<VoucherState>,
}

/// A `batch-settlement` payment requirement (one `accepts[]` entry in a 402).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchRequirements {
    #[serde(default = "batch_scheme")]
    pub scheme: String,

    /// CAIP-2 network identifier, e.g. `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`.
    pub network: String,

    /// Fixed per-request price in atomic units.
    pub amount: String,

    /// Concrete SPL / Token-2022 mint pubkey — never a symbol.
    pub asset: String,

    /// Base58 final payment receiver, normally a server cold wallet.
    pub pay_to: String,

    /// HTTP completion window in seconds.
    pub max_timeout_seconds: u64,

    pub extra: BatchExtra,
}

impl BatchRequirements {
    /// Parse the per-request price as atomic units.
    pub fn amount(&self) -> Result<u64, Error> {
        parse_amount(&self.amount, "amount")
    }

    /// Whether this requirement carries a corrective channel snapshot, i.e. it
    /// came back with `invalid_batch_settlement_svm_cumulative_amount_mismatch`
    /// and tells the client where the server's watermark actually is.
    pub fn is_corrective(&self) -> bool {
        self.extra.channel_state.is_some()
    }

    /// Canonical accepted-object JSON for this requirement.
    pub fn to_accepted_value(&self) -> Result<serde_json::Value, Error> {
        serde_json::to_value(self)
            .map_err(|e| Error::Other(format!("batch requirement serialization failed: {e}")))
    }
}

/// The `PAYMENT-REQUIRED` envelope for a `batch-settlement` challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchRequiredEnvelope {
    pub x402_version: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,

    #[serde(default)]
    pub accepts: Vec<BatchRequirements>,

    /// Set on a corrective 402, e.g.
    /// `invalid_batch_settlement_svm_cumulative_amount_mismatch`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Shared wire objects ──

/// Channel configuration, carried on every client payload.
///
/// Every field is a channel-PDA seed or an immutable channel property, so this
/// is what both sides rederive the channel address from — nothing here may
/// change over a channel's life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchChannelConfig {
    /// Client wallet and channel `payer`. MUST NOT equal `extra.feePayer`: the
    /// program requires distinct payer and payee accounts.
    pub payer: String,

    /// Client-controlled voucher signer; the channel `authorized_signer`. MAY
    /// equal `payer`, MUST NOT equal `extra.feePayer`.
    pub payer_authorizer: String,

    /// MUST equal `PaymentRequirements.payTo`. The sole distribution recipient,
    /// at 10,000 bps.
    pub receiver: String,

    /// Optional; when present MUST equal `extra.receiverAuthorizer`. Authorizes
    /// cooperative closes offchain — not a PDA seed or program account field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_authorizer: Option<String>,

    /// MUST equal `PaymentRequirements.asset`; the channel `mint`.
    pub token: String,

    /// MUST equal `extra.withdrawDelay`; the channel `grace_period`.
    pub withdraw_delay: u32,

    /// Decimal `u64` channel salt.
    pub salt: String,

    /// `u64` slot encoded in `open` and used as a channel-PDA seed.
    pub open_slot: u64,
}

impl BatchChannelConfig {
    /// Parse the channel salt.
    pub fn salt(&self) -> Result<u64, Error> {
        parse_amount(&self.salt, "channelConfig.salt")
    }
}

/// A signed cumulative voucher: the offchain authorization for one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVoucher {
    /// Channel PDA (base58).
    pub channel_id: String,

    /// Cumulative authorized total in atomic units; the program's
    /// `cumulative_amount`. Monotonic across a channel's life.
    pub max_claimable_amount: String,

    /// MUST be [`VOUCHER_EXPIRES_AT`]. The field stays in the signed message
    /// for program compatibility.
    pub expires_at: i64,

    /// Base58 Ed25519 signature by `channelConfig.payerAuthorizer` over the
    /// 50-byte message `0x56 0x01 || channelId || u64(maxClaimableAmount).le ||
    /// i64(expiresAt).le`.
    pub signature: String,
}

impl BatchVoucher {
    /// Parse the cumulative authorized total.
    pub fn max_claimable(&self) -> Result<u64, Error> {
        parse_amount(&self.max_claimable_amount, "voucher.maxClaimableAmount")
    }

    /// The commitment identifier this voucher establishes, as reported in
    /// `SettlementResponse.extra.commitmentId`.
    pub fn commitment_id(&self) -> String {
        format!("{}:{}", self.channel_id, self.max_claimable_amount)
    }
}

/// A server signature authorizing an immediate cooperative close.
///
/// Defined for wire completeness. This SDK never produces one and rejects any
/// it receives: the interoperable close path is the payer-signed
/// `request_close`, and a facilitator must not honor a receiver-authorizer key
/// merely because it appeared in an untrusted request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseAuthorization {
    /// Integer Unix seconds; must satisfy `now < validBefore <= now +
    /// maxTimeoutSeconds`.
    pub valid_before: i64,

    /// Base58 Ed25519 signature by the receiver authorizer.
    pub signature: String,
}

/// The escrow funding carried on a `deposit` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDeposit {
    /// Amount to deposit or top up, in atomic units.
    pub amount: String,

    /// Base64 client-signed `open` or `top_up` transaction for the sponsor to
    /// statically validate, co-sign, and broadcast.
    pub transaction: String,
}

impl BatchDeposit {
    /// Parse the deposited amount.
    pub fn amount(&self) -> Result<u64, Error> {
        parse_amount(&self.amount, "deposit.amount")
    }
}

/// The client authorization carried in `PAYMENT-SIGNATURE.payload`: a tagged
/// union on `type`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum BatchPayload {
    /// Open a channel or top up an existing one, and authorize this request.
    Deposit {
        channel_config: BatchChannelConfig,
        voucher: BatchVoucher,
        deposit: BatchDeposit,
    },

    /// Steady-state paid request: a new cumulative voucher, no transaction.
    Voucher {
        channel_config: BatchChannelConfig,
        voucher: BatchVoucher,
    },

    /// Start a payer-forced channel close. A payment operation, not a paid
    /// request — the resource handler MUST be bypassed. It carries no `amount`:
    /// the program returns all unused escrow or nothing.
    Refund {
        channel_config: BatchChannelConfig,
        /// Base64 client-signed `request_close` transaction, whose Solana fee
        /// payer MUST be `extra.feePayer`.
        transaction: String,
        /// Optional hint for an immediate cooperative close. Never applied
        /// unless an authenticated server confirms it is the latest accepted
        /// voucher; this SDK rejects it outright.
        #[serde(skip_serializing_if = "Option::is_none")]
        voucher: Option<BatchVoucher>,
        /// Optional server authorization for that shortcut. Rejected here.
        #[serde(skip_serializing_if = "Option::is_none")]
        close_authorization: Option<CloseAuthorization>,
    },
}

impl BatchPayload {
    /// The channel configuration every variant carries.
    pub fn channel_config(&self) -> &BatchChannelConfig {
        match self {
            BatchPayload::Deposit { channel_config, .. }
            | BatchPayload::Voucher { channel_config, .. }
            | BatchPayload::Refund { channel_config, .. } => channel_config,
        }
    }

    /// The paid-request voucher, when this payload authorizes a charge.
    /// `refund` returns `None` — its optional voucher is a close hint, not an
    /// authorization to serve.
    pub fn charge_voucher(&self) -> Option<&BatchVoucher> {
        match self {
            BatchPayload::Deposit { voucher, .. } | BatchPayload::Voucher { voucher, .. } => {
                Some(voucher)
            }
            BatchPayload::Refund { .. } => None,
        }
    }

    /// The wire discriminant, for error messages and metrics.
    pub fn type_name(&self) -> &'static str {
        match self {
            BatchPayload::Deposit { .. } => "deposit",
            BatchPayload::Voucher { .. } => "voucher",
            BatchPayload::Refund { .. } => "refund",
        }
    }
}

/// The `PAYMENT-SIGNATURE` envelope for a `batch-settlement` payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPaymentPayload {
    pub x402_version: u64,

    /// The selected requirements, echoed back. MUST equal the server's
    /// `paymentRequirements` for the request.
    pub accepted: BatchRequirements,

    pub payload: BatchPayload,
}

// ── Server-authored redemption payloads ──

/// One voucher claim in a `claim` batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVoucherClaim {
    pub voucher: BatchClaimVoucher,
    /// Base58 Ed25519 voucher signature.
    pub signature: String,
}

/// The voucher body inside a claim: the full channel configuration needed to
/// derive and validate the channel, plus the cumulative amount to settle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchClaimVoucher {
    pub channel_config: BatchChannelConfig,
    pub channel_id: String,
    pub max_claimable_amount: String,
    pub expires_at: i64,
}

/// One channel in a `settle` batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettleChannel {
    pub channel_id: String,
    pub channel_config: BatchChannelConfig,
}

/// The redemption payloads a server (or its batch worker) authors.
///
/// `claim` advances the onchain `settled` watermark from stored vouchers;
/// `settle` pays the newly settled delta to `payTo`. Neither moves through the
/// paid-request path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BatchRedemptionPayload {
    /// One to [`MAX_CLAIMS_PER_BATCH`] voucher claims; program `settle`.
    Claim { claims: Vec<BatchVoucherClaim> },
    /// One or more channels to distribute; program `distribute`.
    Settle { channels: Vec<BatchSettleChannel> },
}

// ── Responses ──

/// Onchain channel snapshot returned in settlement responses and corrective
/// challenges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelStateSnapshot {
    /// Channel PDA (base58).
    pub channel_id: String,

    /// Current `Channel.deposit` ceiling, in atomic units.
    pub balance: String,

    /// Current onchain `Channel.settled` watermark.
    pub total_claimed: String,

    /// `Channel.closure_started_at`, or `0` when no forced close is pending.
    pub withdraw_requested_at: i64,

    /// Server-owned offchain cumulative fixed charge. Present only when the
    /// response is authored by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charged_cumulative_amount: Option<String>,
}

/// The signed voucher proof a corrective 402 carries, so the client can adopt a
/// new cumulative base without trusting the server's word for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoucherState {
    /// The cumulative amount the server holds a signature for.
    pub signed_max_claimable: String,

    /// Expiry in the signed message; [`VOUCHER_EXPIRES_AT`] in this scheme.
    pub expires_at: i64,

    /// Base58 Ed25519 signature the client re-verifies against its own
    /// `payerAuthorizer` key before adopting the snapshot.
    pub signature: String,
}

impl VoucherState {
    /// Parse the signed cumulative amount.
    pub fn signed_max_claimable(&self) -> Result<u64, Error> {
        parse_amount(
            &self.signed_max_claimable,
            "voucherState.signedMaxClaimable",
        )
    }
}

/// Scheme-specific fields nested under `SettlementResponse.extra`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementExtra {
    /// MUST be non-empty for voucher acceptance, e.g.
    /// `channelId:maxClaimableAmount`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitment_id: Option<String>,

    /// Fixed per-request charge; equals `PaymentRequirements.amount`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charged_amount: Option<String>,

    /// Current channel snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_state: Option<ChannelStateSnapshot>,
}

/// The `PAYMENT-RESPONSE` settlement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettlementResponse {
    pub success: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,

    /// Channel `payer`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,

    /// Onchain signature for deposit / top-up / refund-initiation / claim /
    /// settle operations; the empty string for offchain voucher acceptance.
    pub transaction: String,

    /// CAIP-2 network identifier.
    pub network: String,

    /// Amount moved onchain; empty for voucher acceptance and `claim`.
    #[serde(default)]
    pub amount: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<BatchSettlementExtra>,
}

impl BatchSettlementResponse {
    /// A failed settlement carrying `reason` as the machine-readable code.
    pub fn failure(network: &str, reason: &'static str, payer: Option<String>) -> Self {
        Self {
            success: false,
            error_reason: Some(reason.to_string()),
            payer,
            transaction: String::new(),
            network: network.to_string(),
            amount: String::new(),
            extra: None,
        }
    }

    /// The channel snapshot this response carries, when any.
    pub fn channel_state(&self) -> Option<&ChannelStateSnapshot> {
        self.extra.as_ref()?.channel_state.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const CHANNEL: &str = "Chan11111111111111111111111111111111111111";

    fn extra() -> BatchExtra {
        BatchExtra {
            payment_flow: None,
            fee_payer: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
            receiver_authorizer: Some("Auth1111111111111111111111111111111111111".to_string()),
            withdraw_delay: 3600,
            token_program: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            memo: Some("invoice-123".to_string()),
            recent_blockhash: None,
            recent_slot: Some(341_000_000),
            channel_state: None,
            voucher_state: None,
        }
    }

    fn requirements() -> BatchRequirements {
        BatchRequirements {
            scheme: BATCH_SETTLEMENT_SCHEME.to_string(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: "1000".to_string(),
            asset: MINT.to_string(),
            pay_to: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            max_timeout_seconds: 300,
            extra: extra(),
        }
    }

    fn channel_config() -> BatchChannelConfig {
        BatchChannelConfig {
            payer: "Payer111111111111111111111111111111111111".to_string(),
            payer_authorizer: "Payer111111111111111111111111111111111111".to_string(),
            receiver: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".to_string(),
            receiver_authorizer: Some("Auth1111111111111111111111111111111111111".to_string()),
            token: MINT.to_string(),
            withdraw_delay: 3600,
            salt: "42".to_string(),
            open_slot: 341_000_000,
        }
    }

    fn voucher(max_claimable: &str) -> BatchVoucher {
        BatchVoucher {
            channel_id: CHANNEL.to_string(),
            max_claimable_amount: max_claimable.to_string(),
            expires_at: VOUCHER_EXPIRES_AT,
            signature: "sig".to_string(),
        }
    }

    #[test]
    fn requirements_serialize_to_the_canonical_wire_shape() {
        let json = serde_json::to_value(requirements()).unwrap();
        assert_eq!(json["scheme"], "batch-settlement");
        assert_eq!(
            json["payTo"],
            "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY"
        );
        assert_eq!(json["maxTimeoutSeconds"], 300);
        assert_eq!(json["extra"]["withdrawDelay"], 3600);
        assert_eq!(json["extra"]["feePayer"], extra().fee_payer);
        assert_eq!(json["extra"]["recentSlot"], 341_000_000u64);
        // The program id is a network constant, never a wire field: a server
        // must not be able to point the client at a program of its choosing.
        assert!(json["extra"].get("channelProgram").is_none());
        // Absent optionals stay off the wire rather than serializing as null.
        assert!(json["extra"].get("paymentFlow").is_none());
        assert!(json["extra"].get("channelState").is_none());

        let back: BatchRequirements = serde_json::from_value(json).unwrap();
        assert_eq!(back.amount().unwrap(), 1000);
        assert!(!back.is_corrective());
    }

    #[test]
    fn channel_config_and_voucher_use_spec_field_names() {
        let json = serde_json::to_value(channel_config()).unwrap();
        for field in [
            "payer",
            "payerAuthorizer",
            "receiver",
            "receiverAuthorizer",
            "token",
            "withdrawDelay",
            "salt",
            "openSlot",
        ] {
            assert!(json.get(field).is_some(), "missing {field}");
        }
        assert_eq!(json["salt"], "42");
        assert_eq!(json["openSlot"], 341_000_000u64);

        let json = serde_json::to_value(voucher("5000")).unwrap();
        assert_eq!(json["maxClaimableAmount"], "5000");
        assert_eq!(json["expiresAt"], 0);
        // The signer is not on the wire: it is `channelConfig.payerAuthorizer`,
        // so a voucher cannot name a key the channel config does not bind.
        assert!(json.get("signer").is_none());
    }

    #[test]
    fn payload_union_round_trips_every_variant() {
        let deposit = BatchPayload::Deposit {
            channel_config: channel_config(),
            voucher: voucher("1000"),
            deposit: BatchDeposit {
                amount: "100000".to_string(),
                transaction: "b64".to_string(),
            },
        };
        let json = serde_json::to_value(&deposit).unwrap();
        assert_eq!(json["type"], "deposit");
        assert!(json.get("channelConfig").is_some());
        assert!(json.get("channel_config").is_none());
        assert_eq!(json["deposit"]["amount"], "100000");
        assert_eq!(deposit.type_name(), "deposit");
        assert_eq!(
            deposit.charge_voucher().unwrap().max_claimable().unwrap(),
            1000
        );

        let steady = BatchPayload::Voucher {
            channel_config: channel_config(),
            voucher: voucher("5000"),
        };
        assert_eq!(serde_json::to_value(&steady).unwrap()["type"], "voucher");

        let refund = BatchPayload::Refund {
            channel_config: channel_config(),
            transaction: "b64".to_string(),
            voucher: None,
            close_authorization: None,
        };
        let json = serde_json::to_value(&refund).unwrap();
        assert_eq!(json["type"], "refund");
        assert!(json.get("closeAuthorization").is_none());
        assert!(json.get("voucher").is_none());
        // A refund's voucher is a close hint, never an authorization to serve.
        assert!(refund.charge_voucher().is_none());
        assert_eq!(refund.channel_config().salt().unwrap(), 42);

        let back: BatchPayload = serde_json::from_value(json).unwrap();
        assert!(matches!(back, BatchPayload::Refund { .. }));
    }

    #[test]
    fn commitment_id_pairs_the_channel_with_its_watermark() {
        assert_eq!(voucher("5000").commitment_id(), format!("{CHANNEL}:5000"));
    }

    #[test]
    fn settlement_response_matches_the_voucher_acceptance_example() {
        let response = BatchSettlementResponse {
            success: true,
            error_reason: None,
            payer: Some("Payer111111111111111111111111111111111111".to_string()),
            transaction: String::new(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: String::new(),
            extra: Some(BatchSettlementExtra {
                commitment_id: Some(format!("{CHANNEL}:5000")),
                charged_amount: Some("1000".to_string()),
                channel_state: Some(ChannelStateSnapshot {
                    channel_id: CHANNEL.to_string(),
                    balance: "100000".to_string(),
                    total_claimed: "3000".to_string(),
                    withdraw_requested_at: 0,
                    charged_cumulative_amount: Some("5000".to_string()),
                }),
            }),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["success"], true);
        // Offchain acceptance moves no value: both fields are the empty string,
        // not null and not omitted.
        assert_eq!(json["transaction"], "");
        assert_eq!(json["amount"], "");
        assert_eq!(json["extra"]["commitmentId"], format!("{CHANNEL}:5000"));
        assert_eq!(json["extra"]["chargedAmount"], "1000");
        assert_eq!(json["extra"]["channelState"]["totalClaimed"], "3000");
        assert!(json.get("errorReason").is_none());
        assert_eq!(response.channel_state().unwrap().balance, "100000");

        let failed = BatchSettlementResponse::failure(
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            super::super::errors::INVALID_VOUCHER_EXPIRY,
            None,
        );
        assert!(!failed.success);
        assert_eq!(
            failed.error_reason.as_deref(),
            Some(super::super::errors::INVALID_VOUCHER_EXPIRY)
        );
        assert!(failed.channel_state().is_none());
    }

    #[test]
    fn corrective_requirements_carry_the_snapshot_and_voucher_proof() {
        let mut req = requirements();
        req.extra.channel_state = Some(ChannelStateSnapshot {
            channel_id: CHANNEL.to_string(),
            balance: "100000".to_string(),
            total_claimed: "2000".to_string(),
            withdraw_requested_at: 0,
            charged_cumulative_amount: Some("3000".to_string()),
        });
        req.extra.voucher_state = Some(VoucherState {
            signed_max_claimable: "3000".to_string(),
            expires_at: VOUCHER_EXPIRES_AT,
            signature: "sig".to_string(),
        });
        assert!(req.is_corrective());
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(
            json["extra"]["channelState"]["chargedCumulativeAmount"],
            "3000"
        );
        assert_eq!(json["extra"]["voucherState"]["signedMaxClaimable"], "3000");
        let back: BatchRequirements = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.extra
                .voucher_state
                .unwrap()
                .signed_max_claimable()
                .unwrap(),
            3000
        );
    }

    #[test]
    fn redemption_payloads_tag_claim_and_settle() {
        let claim = BatchRedemptionPayload::Claim {
            claims: vec![BatchVoucherClaim {
                voucher: BatchClaimVoucher {
                    channel_config: channel_config(),
                    channel_id: CHANNEL.to_string(),
                    max_claimable_amount: "5000".to_string(),
                    expires_at: VOUCHER_EXPIRES_AT,
                },
                signature: "sig".to_string(),
            }],
        };
        assert_eq!(serde_json::to_value(&claim).unwrap()["type"], "claim");

        let settle = BatchRedemptionPayload::Settle {
            channels: vec![BatchSettleChannel {
                channel_id: CHANNEL.to_string(),
                channel_config: channel_config(),
            }],
        };
        let json = serde_json::to_value(&settle).unwrap();
        assert_eq!(json["type"], "settle");
        assert_eq!(json["channels"][0]["channelId"], CHANNEL);
    }

    #[test]
    fn amount_parsing_rejects_non_numeric_wire_values() {
        let mut req = requirements();
        req.amount = "1e3".to_string();
        assert!(req.amount().is_err());
        let mut cfg = channel_config();
        cfg.salt = "-1".to_string();
        assert!(cfg.salt().is_err());
    }
}
