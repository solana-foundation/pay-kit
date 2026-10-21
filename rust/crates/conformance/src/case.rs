//! The case model.
//!
//! A [`Case`] is one conformance vector before it is filled: its identity,
//! its traceability (spec reference, requirement ids), how its input is
//! produced and what it must yield. `fill` realizes every case by running the
//! Rust kit (see `realize.rs`) and writes the vector the SDK runners consume.
//!
//! Validation happens once, at construction: [`CaseId`], [`ReqId`] and
//! [`SpecRef`] have private fields and fallible constructors, so a malformed
//! id or a spec reference outside the pinned repositories cannot be built.

use std::fmt;

use serde_json::Value;

use crate::mutate::Mutation;

/// Vector id, e.g. `charge-sol-native-build`.
///
/// Lowercase ASCII letters, digits and single dashes; starts with a letter;
/// at most 96 characters. The id is the key every
/// `harness/expectations/<lang>.toml` refers to, so it never changes once
/// published.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaseId(String);

impl CaseId {
    pub fn new(id: &str) -> Result<Self, String> {
        let valid = !id.is_empty()
            && id.len() <= 96
            && id.starts_with(|c: char| c.is_ascii_lowercase())
            && !id.ends_with('-')
            && !id.contains("--")
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if valid {
            Ok(Self(id.to_string()))
        } else {
            Err(format!(
                "invalid case id {id:?}: expected [a-z][a-z0-9-]*, no double or trailing dash, at most 96 chars"
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The Rust identifier the registry macro uses for this case's test.
    pub fn test_name(&self) -> String {
        self.0.replace('-', "_")
    }
}

impl fmt::Display for CaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Requirement id: `MPP-` or `X402-` followed by 10 lowercase hex digits, the
/// prefix of the SHA-256 of the normalised normative sentence (see
/// `reqlint.rs`). The id therefore changes whenever the pinned text changes,
/// which is how the lint detects drift under a mapped requirement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReqId(String);

impl ReqId {
    pub fn new(id: &str) -> Result<Self, String> {
        let hex = SpecRepo::ALL.iter().find_map(|repo| {
            id.strip_prefix(repo.req_prefix())
                .and_then(|rest| rest.strip_prefix('-'))
        });
        match hex {
            Some(hex)
                if hex.len() == 10
                    && hex
                        .chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) =>
            {
                Ok(Self(id.to_string()))
            }
            _ => Err(format!(
                "invalid requirement id {id:?}: expected <MPP|X402|MPPTX|X402TX>-<10 hex>"
            )),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A pinned specification repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SpecRepo {
    /// `external/mpp-specs` (tempoxyz/mpp-specs).
    MppSpecs,
    /// `typescript/external/x402` (x402-foundation/x402).
    X402,
    /// `external/mpp-specs-solana` (solana-foundation/mpp-specs): Solana
    /// method drafts not yet merged upstream (the subscription method).
    MppSpecsSolana,
    /// `external/mpp-specs-txv1` (solana-foundation/mpp-specs
    /// feat/solana-transaction-versions): transaction-version negotiation
    /// for the Solana charge and session methods, not yet merged upstream.
    MppSpecsTxV1,
    /// `external/x402-txv1` (solana-foundation/x402, x402-foundation/x402
    /// PR 3473): SVM transaction-version negotiation for exact, upto and
    /// batch-settlement, not yet merged upstream.
    X402TxV1,
}

impl SpecRepo {
    pub const ALL: [SpecRepo; 5] = [
        SpecRepo::MppSpecs,
        SpecRepo::X402,
        SpecRepo::MppSpecsSolana,
        SpecRepo::MppSpecsTxV1,
        SpecRepo::X402TxV1,
    ];

    /// Prefix of `SpecRef::doc` naming this repository.
    pub fn prefix(self) -> &'static str {
        match self {
            SpecRepo::MppSpecs => "mpp-specs",
            SpecRepo::X402 => "x402",
            SpecRepo::MppSpecsSolana => "mpp-specs-solana",
            SpecRepo::MppSpecsTxV1 => "mpp-specs-txv1",
            SpecRepo::X402TxV1 => "x402-txv1",
        }
    }

    /// Checkout path relative to the pay-kit repository root.
    pub fn checkout(self) -> &'static str {
        match self {
            SpecRepo::MppSpecs => "external/mpp-specs",
            SpecRepo::X402 => "typescript/external/x402",
            SpecRepo::MppSpecsSolana => "external/mpp-specs-solana",
            SpecRepo::MppSpecsTxV1 => "external/mpp-specs-txv1",
            SpecRepo::X402TxV1 => "external/x402-txv1",
        }
    }

    /// Requirement-id prefix for sentences from this repository.
    pub fn req_prefix(self) -> &'static str {
        match self {
            SpecRepo::MppSpecs | SpecRepo::MppSpecsSolana => "MPP",
            SpecRepo::X402 => "X402",
            // The txv1 drafts copy most of the pinned text; a distinct prefix
            // keeps their sentence ids apart from the merged documents'.
            SpecRepo::MppSpecsTxV1 => "MPPTX",
            SpecRepo::X402TxV1 => "X402TX",
        }
    }
}

/// Where a case's rule is written down: a markdown file inside a pinned spec
/// repository, the section heading, and a verbatim quote. `pkc req-lint`
/// fails when the quote no longer appears (whitespace-normalised) in the
/// pinned file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecRef {
    repo: SpecRepo,
    path: String,
    section: String,
    quote: String,
}

impl SpecRef {
    /// `doc` is `<repo>/<path>.md`, e.g.
    /// `mpp-specs/specs/methods/solana/draft-solana-charge-00.md`.
    pub fn new(doc: &str, section: &str, quote: &str) -> Result<Self, String> {
        let (repo, path) = SpecRepo::ALL
            .iter()
            .find_map(|repo| {
                doc.strip_prefix(repo.prefix())
                    .and_then(|rest| rest.strip_prefix('/'))
                    .map(|path| (*repo, path))
            })
            .ok_or_else(|| {
                format!("spec doc {doc:?} must start with a pinned spec checkout prefix (mpp-specs/, x402/, ...)")
            })?;
        if !path.starts_with("specs/") || !path.ends_with(".md") || path.contains("..") {
            return Err(format!(
                "spec doc {doc:?} must be a markdown file under specs/"
            ));
        }
        if section.trim().is_empty() {
            return Err(format!("spec reference to {doc} has an empty section"));
        }
        if quote.trim().len() < 12 {
            return Err(format!(
                "spec reference to {doc} needs a verbatim quote of at least 12 characters"
            ));
        }
        Ok(Self {
            repo,
            path: path.to_string(),
            section: section.to_string(),
            quote: quote.to_string(),
        })
    }

    pub fn repo(&self) -> SpecRepo {
        self.repo
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn doc(&self) -> String {
        format!("{}/{}", self.repo.prefix(), self.path)
    }

    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn quote(&self) -> &str {
        &self.quote
    }
}

/// Which protocol surface a case exercises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Suite {
    Charge,
    Session,
    Subscription,
    X402Exact,
    X402Upto,
    BatchSettlement,
    Protocol,
    CanonicalBytes,
}

impl Suite {
    pub fn as_str(self) -> &'static str {
        match self {
            Suite::Charge => "charge",
            Suite::Session => "session",
            Suite::Subscription => "subscription",
            Suite::X402Exact => "x402-exact",
            Suite::X402Upto => "x402-upto",
            Suite::BatchSettlement => "batch-settlement",
            Suite::Protocol => "protocol",
            Suite::CanonicalBytes => "canonical-bytes",
        }
    }
}

/// The vector ABI's `intent` (schema.ts `ConformanceVector.intent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Intent {
    Charge,
    X402Exact,
    Session,
    X402Upto,
    X402BatchSettlement,
    Subscription,
}

impl Intent {
    pub const ALL: [Intent; 6] = [
        Intent::Charge,
        Intent::X402Exact,
        Intent::Session,
        Intent::X402Upto,
        Intent::X402BatchSettlement,
        Intent::Subscription,
    ];

    /// The intent a vector's `intent` string names.
    pub fn parse(name: &str) -> Option<Intent> {
        Intent::ALL.into_iter().find(|i| i.as_str() == name)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Intent::Charge => "charge",
            Intent::X402Exact => "x402-exact",
            Intent::Session => "session",
            Intent::X402Upto => "x402-upto",
            Intent::X402BatchSettlement => "x402-batch-settlement",
            Intent::Subscription => "subscription",
        }
    }
}

/// The vector ABI's `mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    BuildTransaction,
    VerifyTransaction,
    CanonicalBytes,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::BuildTransaction => "build-transaction",
            Mode::VerifyTransaction => "verify-transaction",
            Mode::CanonicalBytes => "canonical-bytes",
        }
    }
}

/// Minimum execution tier a case needs (DESIGN.md §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Offline,
    Interop,
    OnChain,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Offline => "offline",
            Tier::Interop => "interop",
            Tier::OnChain => "onchain",
        }
    }
}

/// Which SDK role a case tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Client,
    Server,
    Both,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Server => "server",
            Role::Both => "both",
        }
    }
}

/// Bug class a failing case points at (Wycheproof `bugType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BugType {
    Replay,
    AuthBypass,
    Settlement,
    Wire,
    Defaults,
    Malleability,
    Precedence,
}

impl BugType {
    pub fn as_str(self) -> &'static str {
        match self {
            BugType::Replay => "replay",
            BugType::AuthBypass => "auth-bypass",
            BugType::Settlement => "settlement",
            BugType::Wire => "wire",
            BugType::Defaults => "defaults",
            BugType::Malleability => "malleability",
            BugType::Precedence => "precedence",
        }
    }
}

/// The shared reject vocabulary. Exactly `RejectCode` in
/// `harness/src/conformance/schema.ts`; the `reject_codes_match_schema_ts`
/// test keeps the two in lockstep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RejectCode {
    ComputePriceOverCap,
    ComputeLimitOverCap,
    FeePayerNotAuthority,
    FeePayerIsFundsSource,
    DecimalsMismatch,
    SplitsExceedAmount,
    TooManySplits,
    UnexpectedInstruction,
    NoMatchingTransfer,
    AmountMismatch,
    InvalidPayload,
    UnsupportedVersion,
    WrongNetwork,
    PaymentIdentifierRequired,
    InvalidChallenge,
    VoucherExpired,
    VoucherExpiresBeforeSettlement,
    AcceptedMismatch,
    UnexpectedVoucher,
    UnexpectedType,
    ChannelAlreadyOpen,
    ChannelLifetimeExceeded,
    ExpiresAtMismatch,
    NotYetActive,
    DepositNotCeiling,
    ReceiverAuthorizerMismatch,
    ChannelIdMismatch,
    OpenBindingMismatch,
    /// subscription server: the echoed challenge was not issued by this server or does not match the route (HMAC id, realm, method, intent, plan, program, terms).
    ChallengeMismatch,
    /// subscription server: the activation challenge's `expires` is at or before now.
    ChallengeExpired,
    /// subscription server: `subscriptionExpires` is at or before now.
    SubscriptionExpired,
    /// subscription: the bearer proof is missing, bound to another challenge, payer or delegation, or its Ed25519 signature does not verify.
    AuthenticationInvalid,
    /// subscription server: the first-period charge goes to a receiver ATA not owned by `recipient`.
    RecipientMismatch,
    /// subscription server: the subscribe / transfer_subscription pair is missing, misordered, or binds another plan, puller, subscriber, amount or mint than the challenge.
    ActivationScope,
    /// subscription server: the activation fee payer is not `feePayerKey` (sponsored) or the subscriber (unsponsored).
    FeePayerMismatch,
    /// subscription server: the on-chain delegation is not usable at now (missing, foreign, cancelled, unpaid period, authority invalidated).
    SubscriptionInactive,
    /// subscription server: the credential `source` is not the did:pkh:solana of the activation subscriber.
    SourceMismatch,
    UnsupportedScheme,
    PayloadType,
    PaymentFlow,
    TokenProgram,
    VoucherSignature,
    ReceiverBindingUnavailable,
    CloseAuthorization,
    CloseAmountUnsupported,
    CloseState,
    ChannelClosing,
    WithdrawDelayMismatch,
    WithdrawDelayOutOfRange,
    CumulativeAmountMismatch,
    CumulativeExceedsDeposit,
    VoucherExpiry,
    SetupTransaction,
    SettlementSimulation,
    ChannelState,
    RefundTransaction,
    DuplicateSettlement,
}

impl RejectCode {
    pub const ALL: [RejectCode; 57] = [
        RejectCode::ComputePriceOverCap,
        RejectCode::ComputeLimitOverCap,
        RejectCode::FeePayerNotAuthority,
        RejectCode::FeePayerIsFundsSource,
        RejectCode::DecimalsMismatch,
        RejectCode::SplitsExceedAmount,
        RejectCode::TooManySplits,
        RejectCode::UnexpectedInstruction,
        RejectCode::NoMatchingTransfer,
        RejectCode::AmountMismatch,
        RejectCode::InvalidPayload,
        RejectCode::UnsupportedVersion,
        RejectCode::WrongNetwork,
        RejectCode::PaymentIdentifierRequired,
        RejectCode::InvalidChallenge,
        RejectCode::VoucherExpired,
        RejectCode::VoucherExpiresBeforeSettlement,
        RejectCode::AcceptedMismatch,
        RejectCode::UnexpectedVoucher,
        RejectCode::UnexpectedType,
        RejectCode::ChannelAlreadyOpen,
        RejectCode::ChannelLifetimeExceeded,
        RejectCode::ExpiresAtMismatch,
        RejectCode::NotYetActive,
        RejectCode::DepositNotCeiling,
        RejectCode::ReceiverAuthorizerMismatch,
        RejectCode::ChannelIdMismatch,
        RejectCode::OpenBindingMismatch,
        RejectCode::ChallengeMismatch,
        RejectCode::ChallengeExpired,
        RejectCode::SubscriptionExpired,
        RejectCode::AuthenticationInvalid,
        RejectCode::RecipientMismatch,
        RejectCode::ActivationScope,
        RejectCode::FeePayerMismatch,
        RejectCode::SubscriptionInactive,
        RejectCode::SourceMismatch,
        RejectCode::UnsupportedScheme,
        RejectCode::PayloadType,
        RejectCode::PaymentFlow,
        RejectCode::TokenProgram,
        RejectCode::VoucherSignature,
        RejectCode::ReceiverBindingUnavailable,
        RejectCode::CloseAuthorization,
        RejectCode::CloseAmountUnsupported,
        RejectCode::CloseState,
        RejectCode::ChannelClosing,
        RejectCode::WithdrawDelayMismatch,
        RejectCode::WithdrawDelayOutOfRange,
        RejectCode::CumulativeAmountMismatch,
        RejectCode::CumulativeExceedsDeposit,
        RejectCode::VoucherExpiry,
        RejectCode::SetupTransaction,
        RejectCode::SettlementSimulation,
        RejectCode::ChannelState,
        RejectCode::RefundTransaction,
        RejectCode::DuplicateSettlement,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RejectCode::ComputePriceOverCap => "compute-price-over-cap",
            RejectCode::ComputeLimitOverCap => "compute-limit-over-cap",
            RejectCode::FeePayerNotAuthority => "fee-payer-not-authority",
            RejectCode::FeePayerIsFundsSource => "fee-payer-is-funds-source",
            RejectCode::DecimalsMismatch => "decimals-mismatch",
            RejectCode::SplitsExceedAmount => "splits-exceed-amount",
            RejectCode::TooManySplits => "too-many-splits",
            RejectCode::UnexpectedInstruction => "unexpected-instruction",
            RejectCode::NoMatchingTransfer => "no-matching-transfer",
            RejectCode::AmountMismatch => "amount-mismatch",
            RejectCode::InvalidPayload => "invalid-payload",
            RejectCode::UnsupportedVersion => "unsupported-version",
            RejectCode::WrongNetwork => "wrong-network",
            RejectCode::PaymentIdentifierRequired => "payment-identifier-required",
            RejectCode::InvalidChallenge => "invalid-challenge",
            RejectCode::VoucherExpired => "voucher-expired",
            RejectCode::VoucherExpiresBeforeSettlement => "voucher-expires-before-settlement",
            RejectCode::AcceptedMismatch => "accepted-mismatch",
            RejectCode::UnexpectedVoucher => "unexpected-voucher",
            RejectCode::UnexpectedType => "unexpected-type",
            RejectCode::ChannelAlreadyOpen => "channel-already-open",
            RejectCode::ChannelLifetimeExceeded => "channel-lifetime-exceeded",
            RejectCode::ExpiresAtMismatch => "expires-at-mismatch",
            RejectCode::NotYetActive => "not-yet-active",
            RejectCode::DepositNotCeiling => "deposit-not-ceiling",
            RejectCode::ReceiverAuthorizerMismatch => "receiver-authorizer-mismatch",
            RejectCode::ChannelIdMismatch => "channel-id-mismatch",
            RejectCode::OpenBindingMismatch => "open-binding-mismatch",
            RejectCode::ChallengeMismatch => "challenge-mismatch",
            RejectCode::ChallengeExpired => "challenge-expired",
            RejectCode::SubscriptionExpired => "subscription-expired",
            RejectCode::AuthenticationInvalid => "authentication-invalid",
            RejectCode::RecipientMismatch => "recipient-mismatch",
            RejectCode::ActivationScope => "activation-scope",
            RejectCode::FeePayerMismatch => "fee-payer-mismatch",
            RejectCode::SubscriptionInactive => "subscription-inactive",
            RejectCode::SourceMismatch => "source-mismatch",
            RejectCode::UnsupportedScheme => "unsupported-scheme",
            RejectCode::PayloadType => "payload-type",
            RejectCode::PaymentFlow => "payment-flow",
            RejectCode::TokenProgram => "token-program",
            RejectCode::VoucherSignature => "voucher-signature",
            RejectCode::ReceiverBindingUnavailable => "receiver-binding-unavailable",
            RejectCode::CloseAuthorization => "close-authorization",
            RejectCode::CloseAmountUnsupported => "close-amount-unsupported",
            RejectCode::CloseState => "close-state",
            RejectCode::ChannelClosing => "channel-closing",
            RejectCode::WithdrawDelayMismatch => "withdraw-delay-mismatch",
            RejectCode::WithdrawDelayOutOfRange => "withdraw-delay-out-of-range",
            RejectCode::CumulativeAmountMismatch => "cumulative-amount-mismatch",
            RejectCode::CumulativeExceedsDeposit => "cumulative-exceeds-deposit",
            RejectCode::VoucherExpiry => "voucher-expiry",
            RejectCode::SetupTransaction => "setup-transaction",
            RejectCode::SettlementSimulation => "settlement-simulation",
            RejectCode::ChannelState => "channel-state",
            RejectCode::RefundTransaction => "refund-transaction",
            RejectCode::DuplicateSettlement => "duplicate-settlement",
        }
    }
}

impl fmt::Display for RejectCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which fields of the kit's output a generated accept case pins. The values
/// come from the kit; the selection is the reviewed part of the case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pin {
    /// Nothing beyond the outcome (e.g. a session voucher accept).
    Outcome,
    /// Decoded charge transaction shape. `forbidden_programs` is an
    /// assertion the kit's output must satisfy, not a value read from it.
    TransactionShape {
        fee_payer: bool,
        transfers: bool,
        memo: bool,
        max_compute_unit_limit: bool,
        forbidden_programs: Vec<&'static str>,
    },
    /// Decoded x402 envelope fields, by `X402EnvelopeShape` key.
    Envelope(Vec<&'static str>),
    /// `exactBytes` keys (`canonicalJson`, `base64Url`, `bytes`).
    ExactBytes(Vec<&'static str>),
}

/// What a case must yield.
#[derive(Debug, Clone, PartialEq)]
pub enum Expect {
    /// Generated: the kit must accept; the pinned artifact is the kit's
    /// output projected through `Pin`.
    Accept(Pin),
    /// Authored: accept with an artifact taken from the spec text, not from
    /// the kit (the `expect` fields other than `outcome`).
    AcceptAuthored(Value),
    Reject {
        code: RejectCode,
        /// Documentation only; never asserted.
        reason: Option<String>,
    },
}

/// Where the expected value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    /// Computed by running the Rust kit at fill time.
    Generated,
    /// Taken from the spec text. `kit_divergence` documents, with the
    /// reason, that the Rust kit currently disagrees with (or cannot express)
    /// the authored expectation. The positive-control test asserts the
    /// divergence still exists, so fixing the kit forces the entry's removal.
    Authored { kit_divergence: Option<String> },
}

impl Provenance {
    pub fn as_str(&self) -> &'static str {
        match self {
            Provenance::Generated => "generated",
            Provenance::Authored { .. } => "authored",
        }
    }
}

/// How the vector's input is produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Input {
    /// The input is fully specified by the case.
    Static(Value),
    /// A charge verify vector whose `input.transaction` is built by the kit's
    /// client builder from `base.request`, then optionally mutated and
    /// re-signed.
    ChargeTransaction {
        base: Value,
        mutation: Option<Mutation>,
        /// Build the transaction from this input's `request` instead of
        /// `base.request`, so the server verifies a well-formed transaction
        /// against a challenge the kit's builder would refuse (e.g. splits
        /// that consume the whole amount). The vector carries `base`.
        built_from: Option<Value>,
    },
    /// An x402 verify vector whose `input.x402PaymentHeader` carries a
    /// transaction in the scheme_exact_svm §3.1 static layout (see
    /// `x402tx.rs`), optionally mutated, wrapped in an envelope.
    X402Header(Box<X402HeaderSpec>),
    /// A `subscription` vector whose input the kit materializes (activation
    /// credentials built by the kit's client, then edited). See
    /// `realize/subscription.rs`.
    Subscription(Box<crate::realize::subscription::Recipe>),
    /// A session verify vector whose `input.sessionOpenVerify.open` is the
    /// kit client's `open` action for the challenge the kit's session server
    /// issues under `server` (or under `built_from`, so the server verifies
    /// an open built for another challenge), optionally mutated.
    SessionOpen(Box<SessionOpenSpec>),
}

/// Recipe for a session `open` verify vector (`input.sessionOpenVerify`).
#[derive(Debug, Clone, PartialEq)]
pub struct SessionOpenSpec {
    /// The verifying server's configuration (`sessionOpenVerify.server`).
    pub server: Value,
    /// Build the open against the challenge of this configuration instead.
    pub built_from: Option<Value>,
    pub mutation: Option<Mutation>,
}

/// Recipe for an x402 verify vector's payment header.
#[derive(Debug, Clone, PartialEq)]
pub struct X402HeaderSpec {
    /// Route the server is configured with (`x402Server*` inputs).
    pub route: X402Route,
    /// Envelope `x402Version`.
    pub version: u64,
    /// v1 top-level network slug (v1 only).
    pub v1_network: Option<&'static str>,
    /// Overrides applied to the `accepted` object (v2 only) after it is
    /// derived from the route: `(key, value)`; `extra.memo` style dotted
    /// keys address `extra`.
    pub accepted_overrides: Vec<(&'static str, Value)>,
    /// `extensions` object echoed on the envelope.
    pub extensions: Option<Value>,
    /// What the transaction pays (defaults to the route).
    pub pays: Option<X402Payment>,
    /// Memo instruction text. `None` uses the deterministic nonce.
    pub memo: Option<String>,
    pub mutation: Option<Mutation>,
    /// Extra static input keys (e.g. `x402ServerRequiresPaymentIdentifier`).
    pub extra_input: Vec<(&'static str, Value)>,
    /// Message format of the static-layout transaction before `mutation`
    /// (version 1 carries the compute budget in its header, §1.5).
    pub tx_format: crate::tx::MessageFormat,
    /// The sponsor's accepted transaction versions
    /// (`input.x402ServerTransactionVersions`). The route advertises them as
    /// `extra.transactionVersions` (§1.5: the server copies the facilitator's
    /// value) and the client echoes them in `accepted`. `None`: the default
    /// `[0]`, nothing advertised.
    pub server_transaction_versions: Option<&'static [u8]>,
}

/// An x402 server route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402Route {
    pub network: &'static str,
    pub recipient: &'static str,
    pub currency: &'static str,
    pub amount: &'static str,
    /// `extra.memo` the route advertises and the verifier must enforce.
    pub memo: Option<&'static str>,
}

/// What an x402 transaction transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X402Payment {
    pub recipient: &'static str,
    pub mint: &'static str,
    pub amount: &'static str,
}

/// One conformance case.
#[derive(Debug, Clone)]
pub struct Case {
    pub id: CaseId,
    /// Output file under `harness/vectors/`.
    pub file: &'static str,
    pub suite: Suite,
    pub intent: Intent,
    pub mode: Mode,
    pub tier: Tier,
    pub role: Role,
    pub bug_type: BugType,
    pub requirements: Vec<ReqId>,
    pub spec: SpecRef,
    pub description: String,
    pub input: Input,
    pub expect: Expect,
    pub provenance: Provenance,
}

/// Fluent constructor so registry entries stay readable. Every field without
/// a sensible default is a required argument of [`CaseBuilder::new`].
pub struct CaseBuilder {
    case: Case,
}

impl CaseBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        file: &'static str,
        suite: Suite,
        intent: Intent,
        mode: Mode,
        role: Role,
        bug_type: BugType,
        spec: SpecRef,
        description: &str,
        input: Input,
        expect: Expect,
    ) -> Self {
        Self {
            case: Case {
                id: CaseId::new(id).unwrap_or_else(|e| panic!("{e}")),
                file,
                suite,
                intent,
                mode,
                tier: Tier::Offline,
                role,
                bug_type,
                requirements: Vec::new(),
                spec,
                description: description.to_string(),
                input,
                expect,
                provenance: Provenance::Generated,
            },
        }
    }

    pub fn requirements(mut self, ids: &[&str]) -> Self {
        self.case.requirements = ids
            .iter()
            .map(|id| ReqId::new(id).unwrap_or_else(|e| panic!("{}: {e}", self.case.id)))
            .collect();
        self
    }

    pub fn authored(mut self, kit_divergence: Option<&str>) -> Self {
        self.case.provenance = Provenance::Authored {
            kit_divergence: kit_divergence.map(str::to_string),
        };
        self
    }

    pub fn build(self) -> Case {
        self.case
    }
}

/// Shorthand for a [`SpecRef`] in registry code; panics on an invalid
/// reference so a bad registry entry fails every test, not just one.
pub fn spec(doc: &str, section: &str, quote: &str) -> SpecRef {
    SpecRef::new(doc, section, quote).unwrap_or_else(|e| panic!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_id_rejects_malformed() {
        for bad in [
            "",
            "Upper",
            "1lead",
            "trail-",
            "dou--ble",
            "under_score",
            "a b",
        ] {
            assert!(CaseId::new(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(CaseId::new("charge-sol-native-build").is_ok());
    }

    #[test]
    fn req_id_rejects_malformed() {
        for bad in [
            "MPP-123",
            "MPP-0123456789a",
            "FOO-0123456789",
            "MPP-ABCDEF0123",
        ] {
            assert!(ReqId::new(bad).is_err(), "{bad:?} should be rejected");
        }
        assert!(ReqId::new("MPP-0123456789").is_ok());
        assert!(ReqId::new("X402-abcdef0123").is_ok());
        assert!(ReqId::new("X402TX-abcdef0123").is_ok());
        assert!(ReqId::new("MPPTX-abcdef0123").is_ok());
    }

    #[test]
    fn spec_ref_requires_pinned_repo_and_quote() {
        assert!(SpecRef::new("rfc/thing.md", "1", "a long enough quote").is_err());
        assert!(SpecRef::new("x402/specs/a.md", "", "a long enough quote").is_err());
        assert!(SpecRef::new("x402/specs/a.md", "1", "short").is_err());
        assert!(SpecRef::new("x402/specs/../a.md", "1", "a long enough quote").is_err());
        let ok = SpecRef::new("x402/specs/a.md", "1", "a long enough quote").unwrap();
        assert_eq!(ok.doc(), "x402/specs/a.md");
    }

    #[test]
    fn reject_codes_match_schema_ts() {
        let schema =
            std::fs::read_to_string(crate::repo_root().join("harness/src/conformance/schema.ts"))
                .unwrap();
        let start = schema.find("export type RejectCode =").unwrap();
        let mut ts = Vec::new();
        for line in schema[start..].lines().skip(1) {
            let line = line.trim();
            if line.starts_with("//") || line.is_empty() {
                continue;
            }
            let Some(code) = line.strip_prefix("| \"").and_then(|l| l.split('"').next()) else {
                break;
            };
            ts.push(code);
            if line.ends_with(';') {
                break;
            }
        }
        let rust: Vec<&str> = RejectCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(ts, rust);
    }
}
