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

/// `extra.withdrawDelay`: "MUST be an integer from `900` through `2592000`".
/// Any JSON number parses here so a fractional or negative value is refused
/// with the range code rather than as a malformed challenge; the range itself
/// is enforced by `check_withdraw_delay`.
fn withdraw_delay_seconds<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    let value = serde_json::Number::deserialize(deserializer)?;
    value
        .as_u64()
        .and_then(|seconds| u32::try_from(seconds).ok())
        .ok_or_else(|| {
            D::Error::custom(format!(
                "{}: withdrawDelay {value} is not an integer number of seconds from \
                 {MIN_WITHDRAW_DELAY_SECONDS} through {MAX_WITHDRAW_DELAY_SECONDS}",
                super::errors::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE
            ))
        })
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

    /// Transaction message versions the server accepts (`0`, `1`). Absent
    /// means `[0]`. See `core::tx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_versions: Option<Vec<crate::core::tx::TxVersion>>,

    /// Base58 server-controlled key that authenticates an optional immediate
    /// cooperative close to the facilitator. Not a payment-channel account
    /// field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_authorizer: Option<String>,

    /// Forced-close grace period in seconds, encoded exactly as the program
    /// `grace_period`. Must be in
    /// [`MIN_WITHDRAW_DELAY_SECONDS`]`..=`[`MAX_WITHDRAW_DELAY_SECONDS`] and at
    /// least `maxTimeoutSeconds`. A non-integer value does not parse, and
    /// the refusal carries `invalid_batch_settlement_svm_withdraw_delay_out_of_range`.
    #[serde(deserialize_with = "withdraw_delay_seconds")]
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

    /// Server-suggested escrow target in atomic units. Clients may clamp this
    /// to a stricter local limit, especially for server-signed channels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_deposit: Option<String>,

    /// Voucher-signing mode: `"client"` (default) or `"server"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voucher_signer: Option<String>,

    /// Base58 resource-operator key; REQUIRED in server mode and MUST be absent
    /// in client mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,

    /// Facilitator idle window in seconds, after which an `Open` channel with no
    /// facilitator-visible lifecycle activity MAY be abandon-closed at its
    /// onchain `settled` watermark. This server runs no idle policy and so
    /// never advertises one; absent means the facilitator does not idle-close.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_idle_secs: Option<u64>,

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

    /// Optional. Omitted or `"client"` selects client mode; `"server"` selects
    /// server mode, binds `payerAuthorizer` to `extra.operator`, and MUST equal
    /// `extra.voucherSigner`. Only client mode is accepted here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voucher_signer: Option<String>,
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

/// The expiring payer proof of server mode (`BatchAuthorization`, spec §4.2):
/// a bearer credential authorizing one metered request up to `authorizedAmount`
/// on a channel whose `authorized_signer` is the operator.
///
/// Clients issue this proof only after an explicit local trust grant for the
/// advertised operator. Resource-server support is independent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchAuthorization {
    /// MUST be `"proof"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Channel PDA (base58).
    pub channel_id: String,
    /// MUST equal `channelConfig.payer`.
    pub payer: String,
    /// Fresh opaque single-use request identifier (1 through 256 UTF-8 bytes).
    pub request_id: String,
    /// Maximum charge in atomic units; MUST equal `PaymentRequirements.amount`.
    pub authorized_amount: String,
    /// Integer Unix seconds; the server requires `now < expiresAt`.
    pub expires_at: i64,
    /// Base58 payer signature over the `x402-batch-authorization-v2` message.
    pub signature: String,
}

/// The receiver authorizer's signature binding one exact cooperative close
/// (`seal`, or a server-enriched `refund`), spec §4.2.
///
/// The signed bytes are the SHA-256 digest from
/// [`super::close_authorization_digest`]. A client never authors one: the
/// resource server adds it before forwarding a close to a separate
/// facilitator, and the facilitator verifies it against the channel's bound
/// key ([`super::verify_close_authorization`]), never against a key that merely
/// appears in the request. This SDK's server self-facilitates, so it closes a
/// channel bound to its own key without producing one.
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
        /// REQUIRED in client mode, absent in server mode (spec §4.3). Optional
        /// on the wire so a server-mode deposit still parses and can be refused
        /// with `invalid_batch_settlement_svm_payload_type` instead of failing
        /// deserialization with a generic error.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        voucher: Option<BatchVoucher>,
        deposit: BatchDeposit,
        /// Server-mode payer proof, carried instead of `voucher` there.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authorization: Option<BatchAuthorization>,
    },

    /// Steady-state paid request: a new cumulative voucher, no transaction.
    Voucher {
        channel_config: BatchChannelConfig,
        voucher: BatchVoucher,
    },

    /// Server-mode steady-state request: an expiring payer proof instead of a
    /// client-signed voucher.
    Authorization {
        channel_config: BatchChannelConfig,
        authorization: BatchAuthorization,
    },

    /// Close the channel and return its unused escrow (spec §3, §4.3). A
    /// payment operation, not a paid request — the resource handler MUST be
    /// bypassed.
    Refund(BatchRefund),
}

/// Who authorizes a `refund`: exactly one of the client-mode voucher or the
/// server-mode payer proof (spec §4.3). A refund carrying neither, or both,
/// does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefundSigner {
    /// Client mode: the server's accepted cumulative, signed by
    /// `channelConfig.payerAuthorizer` (`expiresAt` `0`).
    Client(BatchVoucher),
    /// Server mode: the payer's close-intent proof (`authorizedAmount` `"0"`).
    Server(BatchAuthorization),
}

/// The body of a `refund` payload.
///
/// A refund is a cooperative close by default: the facilitator applies the
/// accepted voucher with `settle_and_seal` and a sealed `distribute`,
/// returning `deposit - settled` to the payer at once. `transaction` is the
/// retry after `invalid_batch_settlement_svm_receiver_binding_unavailable`: a
/// payer-signed `request_close` the facilitator co-signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRefund", into = "RawRefund")]
pub struct BatchRefund {
    pub channel_config: BatchChannelConfig,
    pub signer: RefundSigner,
    /// Base64 payer-signed `request_close` whose Solana fee payer is
    /// `extra.feePayer`. Omitted unless retrying after the binding was
    /// unavailable.
    pub transaction: Option<String>,
    /// Added by the server before forwarding to a separate facilitator; never
    /// client-authored.
    pub close_authorization: Option<CloseAuthorization>,
    /// A partial-refund amount, which this scheme does not support: its
    /// presence is refused with
    /// `invalid_batch_settlement_svm_close_amount_unsupported`. Never set when
    /// building a payload.
    pub amount: Option<String>,
}

impl BatchRefund {
    /// A client-mode cooperative refund at `voucher` (the accepted cumulative).
    pub fn client(channel_config: BatchChannelConfig, voucher: BatchVoucher) -> Self {
        Self {
            channel_config,
            signer: RefundSigner::Client(voucher),
            transaction: None,
            close_authorization: None,
            amount: None,
        }
    }

    /// The client-mode voucher, when this is a client-mode refund.
    pub fn voucher(&self) -> Option<&BatchVoucher> {
        match &self.signer {
            RefundSigner::Client(voucher) => Some(voucher),
            RefundSigner::Server(_) => None,
        }
    }
}

/// The wire shape of [`BatchRefund`], before the signer union is enforced.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRefund {
    channel_config: BatchChannelConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    voucher: Option<BatchVoucher>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<BatchAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transaction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    close_authorization: Option<CloseAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
}

impl TryFrom<RawRefund> for BatchRefund {
    type Error = String;

    fn try_from(raw: RawRefund) -> Result<Self, Self::Error> {
        let signer = match (raw.voucher, raw.authorization) {
            (Some(voucher), None) => RefundSigner::Client(voucher),
            (None, Some(authorization)) => RefundSigner::Server(authorization),
            // The spec code travels in the message, so a server refusing the
            // payload reports it rather than a generic parse failure.
            (None, None) => {
                return Err(format!(
                    "{}: a refund carries the accepted voucher in client mode or the \
                     payer authorization in server mode, and this one carries neither",
                    super::errors::INVALID_PAYLOAD_TYPE
                ))
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "{}: a refund carries a voucher (client mode) or an authorization \
                     (server mode), not both",
                    super::errors::INVALID_PAYLOAD_TYPE
                ))
            }
        };
        Ok(Self {
            channel_config: raw.channel_config,
            signer,
            transaction: raw.transaction,
            close_authorization: raw.close_authorization,
            amount: raw.amount,
        })
    }
}

impl From<BatchRefund> for RawRefund {
    fn from(refund: BatchRefund) -> Self {
        let (voucher, authorization) = match refund.signer {
            RefundSigner::Client(voucher) => (Some(voucher), None),
            RefundSigner::Server(authorization) => (None, Some(authorization)),
        };
        Self {
            channel_config: refund.channel_config,
            voucher,
            authorization,
            transaction: refund.transaction,
            close_authorization: refund.close_authorization,
            amount: refund.amount,
        }
    }
}

impl BatchPayload {
    /// The channel configuration every variant carries.
    pub fn channel_config(&self) -> &BatchChannelConfig {
        match self {
            BatchPayload::Deposit { channel_config, .. }
            | BatchPayload::Voucher { channel_config, .. }
            | BatchPayload::Authorization { channel_config, .. }
            | BatchPayload::Refund(BatchRefund { channel_config, .. }) => channel_config,
        }
    }

    /// The paid-request voucher, when this payload authorizes a charge.
    /// `refund` returns `None` — its voucher fixes the close watermark, it
    /// authorizes no charge — and so does `authorization`, which carries a
    /// payer proof rather than a voucher.
    pub fn charge_voucher(&self) -> Option<&BatchVoucher> {
        match self {
            BatchPayload::Deposit { voucher, .. } => voucher.as_ref(),
            BatchPayload::Voucher { voucher, .. } => Some(voucher),
            BatchPayload::Authorization { .. } | BatchPayload::Refund(_) => None,
        }
    }

    /// The wire discriminant, for error messages and metrics.
    pub fn type_name(&self) -> &'static str {
        match self {
            BatchPayload::Deposit { .. } => "deposit",
            BatchPayload::Voucher { .. } => "voucher",
            BatchPayload::Authorization { .. } => "authorization",
            BatchPayload::Refund(_) => "refund",
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
//
// Every server-authored entry shares one shape — `channelId` plus
// `channelConfig`, with vouchers as [`BatchVoucher`] objects — across `claim`,
// `settle`, and `seal` (spec §4.5). This self-facilitating server redeems
// through its own lifecycle methods rather than over the wire, so these types
// exist to interoperate with a standalone facilitator.

/// One channel in a `claim` batch: the full configuration needed to derive
/// and validate the channel, plus the latest accepted voucher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchVoucherClaim {
    pub channel_id: String,
    pub channel_config: BatchChannelConfig,
    /// Latest accepted voucher; its `maxClaimableAmount` becomes the new
    /// onchain `settled` watermark. `expiresAt` MUST be `0`.
    pub voucher: BatchVoucher,
}

/// One channel in a `settle` batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSettleChannel {
    pub channel_id: String,
    pub channel_config: BatchChannelConfig,
}

/// One to [`MAX_CLAIMS_PER_BATCH`] redemption entries: the only batch sizes a
/// `claim` or `settle` payload may carry (spec §4.5, "`claims[]` MUST contain
/// between one and four entries so the instruction pairs fit in a legacy
/// Solana transaction without address lookup tables").
///
/// The bound is enforced at construction and at parse time, so an empty or
/// oversized batch never exists as a value: a facilitator cannot silently
/// truncate a batch it was never able to receive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<T>", into = "Vec<T>")]
#[serde(bound(
    serialize = "T: Serialize + Clone",
    deserialize = "T: Deserialize<'de>"
))]
pub struct RedemptionBatch<T>(Vec<T>);

impl<T> RedemptionBatch<T> {
    /// Wrap `entries`, refusing an empty batch or one over
    /// [`MAX_CLAIMS_PER_BATCH`].
    pub fn new(entries: Vec<T>) -> Result<Self, Error> {
        if entries.is_empty() || entries.len() > MAX_CLAIMS_PER_BATCH {
            return Err(Error::Other(format!(
                "a redemption batch must carry 1 through {MAX_CLAIMS_PER_BATCH} entries, got {}",
                entries.len()
            )));
        }
        Ok(Self(entries))
    }

    /// The entries, in submission order.
    pub fn entries(&self) -> &[T] {
        &self.0
    }

    /// Consume the batch into its entries.
    pub fn into_entries(self) -> Vec<T> {
        self.0
    }
}

impl<T> TryFrom<Vec<T>> for RedemptionBatch<T> {
    type Error = String;

    fn try_from(entries: Vec<T>) -> Result<Self, Self::Error> {
        Self::new(entries).map_err(|e| e.to_string())
    }
}

impl<T> From<RedemptionBatch<T>> for Vec<T> {
    fn from(batch: RedemptionBatch<T>) -> Self {
        batch.0
    }
}

/// The redemption payloads a server (or its batch worker) authors.
///
/// `claim` advances the onchain `settled` watermark from stored vouchers;
/// `settle` pays the newly settled delta to `payTo`; `seal` finalizes a
/// `Closing` channel with the server's latest voucher during the grace period.
/// None of them moves through the paid-request path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum BatchRedemptionPayload {
    /// One to [`MAX_CLAIMS_PER_BATCH`] channels to claim in one transaction;
    /// program `settle`.
    Claim {
        claims: RedemptionBatch<BatchVoucherClaim>,
    },
    /// One to [`MAX_CLAIMS_PER_BATCH`] channels to distribute in one
    /// transaction; program `distribute`.
    Settle {
        channels: RedemptionBatch<BatchSettleChannel>,
    },
    /// Apply the server's latest voucher to a `Closing` channel with
    /// `settle_and_seal` and pay out with a sealed `distribute`, before the
    /// payer's grace period ends. A standalone facilitator authenticates the
    /// server through `closeAuthorization`.
    Seal(Box<BatchSeal>),
}

/// The single-channel body of a `seal` payload (spec §4.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSeal {
    pub channel_id: String,
    pub channel_config: BatchChannelConfig,
    /// Latest accepted voucher; its `maxClaimableAmount` becomes the final
    /// settled watermark. `expiresAt` MUST be `0`.
    pub voucher: BatchVoucher,
    /// Receiver-authorizer signature binding this exact close. REQUIRED unless
    /// the facilitator authenticates the server out of band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub close_authorization: Option<CloseAuthorization>,
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

    /// Server-signed cumulative voucher confirming a metered authorization.
    /// Present when `voucherSigner` is `"server"`; clients verify this proof
    /// instead of trusting an optional reported cumulative watermark.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher: Option<BatchVoucher>,
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
            min_deposit: None,
            channel_state: None,
            voucher_state: None,
            transaction_versions: None,
            voucher_signer: None,
            operator: None,
            max_idle_secs: None,
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
            voucher_signer: None,
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
            voucher: Some(voucher("1000")),
            deposit: BatchDeposit {
                amount: "100000".to_string(),
                transaction: "b64".to_string(),
            },
            authorization: None,
        };
        let json = serde_json::to_value(&deposit).unwrap();
        assert_eq!(json["type"], "deposit");
        assert!(json.get("authorization").is_none());
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

        // The default refund is cooperative: the accepted voucher, no
        // transaction.
        let refund = BatchPayload::Refund(BatchRefund::client(channel_config(), voucher("5000")));
        let json = serde_json::to_value(&refund).unwrap();
        assert_eq!(json["type"], "refund");
        assert_eq!(json["voucher"]["maxClaimableAmount"], "5000");
        assert!(json.get("closeAuthorization").is_none());
        assert!(json.get("transaction").is_none());
        assert!(json.get("authorization").is_none());
        assert!(json.get("amount").is_none());
        // A refund's voucher fixes the close, it never authorizes a serve.
        assert!(refund.charge_voucher().is_none());
        assert_eq!(refund.channel_config().salt().unwrap(), 42);

        let back: BatchPayload = serde_json::from_value(json.clone()).unwrap();
        assert!(
            matches!(back, BatchPayload::Refund(ref r) if r.voucher() == Some(&voucher("5000")))
        );

        // The voucher is REQUIRED in client mode: a request_close alone is not
        // a refund, and the refusal carries the payload-type code.
        let mut bare = json.clone();
        bare.as_object_mut().unwrap().remove("voucher");
        bare["transaction"] = serde_json::json!("b64");
        let err = serde_json::from_value::<BatchPayload>(bare).unwrap_err();
        assert!(
            err.to_string()
                .contains(super::super::errors::INVALID_PAYLOAD_TYPE),
            "{err}"
        );
        // Both a voucher and a server-mode proof are not one variant either.
        let mut both = json;
        both["authorization"] = serde_json::json!({
            "type": "proof",
            "channelId": CHANNEL,
            "payer": "Payer111111111111111111111111111111111111",
            "requestId": "refund-1",
            "authorizedAmount": "0",
            "expiresAt": 1_758_215_100,
            "signature": "sig"
        });
        assert!(serde_json::from_value::<BatchPayload>(both).is_err());

        // A server-mode request parses, so the server can refuse it by name.
        let authorization: BatchPayload = serde_json::from_value(serde_json::json!({
            "type": "authorization",
            "channelConfig": serde_json::to_value(channel_config()).unwrap(),
            "authorization": {
                "type": "proof",
                "channelId": CHANNEL,
                "payer": "Payer111111111111111111111111111111111111",
                "requestId": "req-1",
                "authorizedAmount": "1000",
                "expiresAt": 1_758_215_100,
                "signature": "sig"
            }
        }))
        .unwrap();
        assert_eq!(authorization.type_name(), "authorization");
        assert!(authorization.charge_voucher().is_none());
        // A server-mode deposit carries a proof and no voucher, and must still
        // parse so the server can refuse it by type.
        let delegated: BatchPayload = serde_json::from_value(serde_json::json!({
            "type": "deposit",
            "channelConfig": serde_json::to_value(channel_config()).unwrap(),
            "deposit": { "amount": "100000", "transaction": "b64" },
            "authorization": {
                "type": "proof",
                "channelId": CHANNEL,
                "payer": "Payer111111111111111111111111111111111111",
                "requestId": "req-1",
                "authorizedAmount": "1000",
                "expiresAt": 1_758_215_100,
                "signature": "sig"
            }
        }))
        .unwrap();
        assert!(matches!(
            delegated,
            BatchPayload::Deposit {
                voucher: None,
                authorization: Some(_),
                ..
            }
        ));
        assert!(delegated.charge_voucher().is_none());
        // And a refund that names an amount keeps it, so the server can refuse
        // it with the dedicated code instead of silently ignoring it.
        let partial: BatchPayload = serde_json::from_value(serde_json::json!({
            "type": "refund",
            "channelConfig": serde_json::to_value(channel_config()).unwrap(),
            "voucher": serde_json::to_value(voucher("5000")).unwrap(),
            "transaction": "b64",
            "amount": "1500"
        }))
        .unwrap();
        assert!(
            matches!(partial, BatchPayload::Refund(BatchRefund { amount: Some(ref a), .. }) if a == "1500")
        );
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
                voucher: None,
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
    fn redemption_payloads_share_one_entry_shape() {
        let claim = BatchRedemptionPayload::Claim {
            claims: RedemptionBatch::new(vec![BatchVoucherClaim {
                channel_id: CHANNEL.to_string(),
                channel_config: channel_config(),
                voucher: voucher("5000"),
            }])
            .unwrap(),
        };
        let json = serde_json::to_value(&claim).unwrap();
        assert_eq!(json["type"], "claim");
        // Spec 4.5: `channelId` + `channelConfig` at the entry level, and the
        // voucher is a plain `BatchVoucher` with its signature inside.
        assert_eq!(json["claims"][0]["channelId"], CHANNEL);
        assert!(json["claims"][0].get("channelConfig").is_some());
        assert_eq!(json["claims"][0]["voucher"]["signature"], "sig");
        assert!(json["claims"][0].get("signature").is_none());
        assert!(json["claims"][0]["voucher"].get("channelConfig").is_none());

        let settle = BatchRedemptionPayload::Settle {
            channels: RedemptionBatch::new(vec![BatchSettleChannel {
                channel_id: CHANNEL.to_string(),
                channel_config: channel_config(),
            }])
            .unwrap(),
        };
        let json = serde_json::to_value(&settle).unwrap();
        assert_eq!(json["type"], "settle");
        assert_eq!(json["channels"][0]["channelId"], CHANNEL);

        let seal = BatchRedemptionPayload::Seal(Box::new(BatchSeal {
            channel_id: CHANNEL.to_string(),
            channel_config: channel_config(),
            voucher: voucher("5000"),
            close_authorization: Some(CloseAuthorization {
                valid_before: 1_785_341_100,
                signature: "close-sig".to_string(),
            }),
        }));
        let json = serde_json::to_value(&seal).unwrap();
        // The tag sits beside the body's fields, matching the spec example.
        assert_eq!(json["type"], "seal");
        assert_eq!(json["channelId"], CHANNEL);
        assert_eq!(json["voucher"]["maxClaimableAmount"], "5000");
        assert_eq!(json["closeAuthorization"]["validBefore"], 1_785_341_100);
        let back: BatchRedemptionPayload = serde_json::from_value(json).unwrap();
        assert!(matches!(back, BatchRedemptionPayload::Seal(body) if body.channel_id == CHANNEL));
    }

    #[test]
    fn redemption_batches_carry_one_to_four_entries() {
        let entry = || {
            serde_json::json!({
                "channelId": CHANNEL,
                "channelConfig": serde_json::to_value(channel_config()).unwrap(),
                "voucher": serde_json::to_value(voucher("5000")).unwrap(),
            })
        };
        let claim = |n: usize| serde_json::json!({ "type": "claim", "claims": (0..n).map(|_| entry()).collect::<Vec<_>>() });
        for n in 1..=MAX_CLAIMS_PER_BATCH {
            let parsed: BatchRedemptionPayload = serde_json::from_value(claim(n)).unwrap();
            assert!(
                matches!(parsed, BatchRedemptionPayload::Claim { claims } if claims.entries().len() == n)
            );
        }
        // Below the minimum and above the transaction-size bound never parse.
        for n in [0, MAX_CLAIMS_PER_BATCH + 1] {
            let err = serde_json::from_value::<BatchRedemptionPayload>(claim(n)).unwrap_err();
            assert!(err.to_string().contains("1 through 4"), "{err}");
        }
        let settle = serde_json::json!({ "type": "settle", "channels": [] });
        assert!(serde_json::from_value::<BatchRedemptionPayload>(settle).is_err());
        assert!(RedemptionBatch::<u8>::new(vec![]).is_err());
        assert!(RedemptionBatch::new(vec![0u8; 5]).is_err());
    }

    #[test]
    fn a_non_integer_withdraw_delay_is_refused_with_the_range_code() {
        let mut json = serde_json::to_value(requirements()).unwrap();
        for bad in [
            serde_json::json!(900.5),
            serde_json::json!(-900),
            serde_json::json!(4_294_967_296u64),
        ] {
            json["extra"]["withdrawDelay"] = bad.clone();
            let err = serde_json::from_value::<BatchRequirements>(json.clone()).unwrap_err();
            assert!(
                err.to_string()
                    .contains(super::super::errors::INVALID_WITHDRAW_DELAY_OUT_OF_RANGE),
                "{bad}: {err}"
            );
        }
        // Positive control: an integer parses (its range is checked later).
        json["extra"]["withdrawDelay"] = serde_json::json!(899);
        let parsed: BatchRequirements = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.extra.withdraw_delay, 899);
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
