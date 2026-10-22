//! MPP session (Solana) transaction versions: the `transactionVersions`
//! method detail of the session challenge, from the pinned draft
//! (`external/mpp-specs-txv1`, solana-foundation/mpp-specs
//! feat/solana-transaction-versions).
//!
//! Single-shot coverage is the challenge wire: the session request parsed and
//! re-encoded through the SDK's own session schema (`sessionWire`). The
//! version admission of client-submitted `open` and `topUp` transactions
//! needs a session open/topUp verify mode (a session server configured from
//! the vector plus a built open transaction) that the vector ABI does not
//! have yet; see the branch report.

use serde_json::{json, Value};

use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role,
    SessionOpenSpec, SpecRef, Suite,
};
use crate::mutate::Mutation;
use crate::tx::MessageFormat;

const SESSION: &str = "mpp-specs-txv1/specs/methods/solana/draft-solana-session-00.md";
const FILE: &str = "session-tx-versions.json";

const ACCEPT_LISTED: &str = "MPPTX-102b6dc2a5";
const NO_LEGACY: &str = "MPPTX-5b29a4494f";
const OPEN_VERSION: &str = "MPPTX-5410e1de47";
const TOPUP_VERSION: &str = "MPPTX-4563533e08";

fn field_spec() -> SpecRef {
    spec(
        SESSION,
        "Method Details",
        "Servers MUST accept every version they list, MUST reject any other version, and MUST NOT list 1 unless the enable_tx_v1 feature gate",
    )
}

fn legacy_spec() -> SpecRef {
    spec(
        SESSION,
        "Transaction Versions",
        "Legacy messages are not supported: servers MUST NOT advertise \"legacy\" and MUST reject a legacy message.",
    )
}

/// A fresh session challenge (the session-wire golden's request) whose
/// methodDetails carry `versions` as `transactionVersions`.
fn request(versions: Value) -> Value {
    json!({ "sessionWire": { "shape": "request", "value": {
        "amount": "100",
        "currency": "USDC",
        "description": "metered inference",
        "methodDetails": {
            "channelProgram": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX",
            "decimals": 6,
            "gracePeriodSeconds": 900,
            "network": "devnet",
            "recentBlockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N",
            "recentSlot": "250000000",
            "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "transactionVersions": versions
        },
        "minimumDeposit": "1000",
        "recipient": "11111111111111111111111111111111",
        "suggestedDeposit": "5000",
        "unitType": "request"
    } } })
}

fn wire(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    versions: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        FILE,
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        spec,
        description,
        Input::Static(request(versions)),
        expect,
    )
    .requirements(reqs)
}

fn golden() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"]))
}

fn reject(reason: &str) -> Expect {
    Expect::Reject {
        code: RejectCode::InvalidPayload,
        reason: Some(reason.to_string()),
    }
}

const REJECT_UNADVERTISED: &str = "MPPTX-27a6fd4f3f";
const V1_LIMITS_SET: &str = "MPPTX-d53a9f42dd";
const V1_NO_BUDGET_IX: &str = "MPPTX-8a036b6610";
const V1_REJECT_BUDGET_IX: &str = "MPPTX-46848f6fce";
const V1_PRICE_CAP: &str = "MPPTX-8a988b0f7a";

fn open_spec() -> SpecRef {
    spec(
        SESSION,
        "Action: \"open\"",
        "| transaction | string | REQUIRED | Base64-encoded (standard alphabet, padded) signed or partially signed transaction; its message version MUST be one the challenge advertises ({{transaction-versions}}) |",
    )
}

fn admission_spec() -> SpecRef {
    spec(
        SESSION,
        "Transaction Versions",
        "Servers MUST reject a transaction whose version is not advertised, or which references an address lookup table, with the malformed-credential problem type, before inspecting any instruction.",
    )
}

/// The verifying session server: client vouchers, client-paid opens, USDC
/// on devnet; `versions` is its accepted (and advertised) set.
fn session_server(versions: Option<Value>) -> Value {
    let mut server = json!({
        "operator": crate::keys::X402_OFFER_FEE_PAYER,
        "recipient": crate::keys::X402_PAY_TO,
        "currency": "USDC",
        "decimals": 6,
        "network": "devnet",
        "amount": "25",
        "minimumDeposit": "100",
        "suggestedDeposit": "1000",
    });
    if let Some(versions) = versions {
        server["transactionVersions"] = versions;
    }
    server
}

#[allow(clippy::too_many_arguments)]
fn open_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    server: Value,
    built_from: Option<Value>,
    mutation: Option<Mutation>,
    expect: Expect,
) -> CaseBuilder {
    let description = match &mutation {
        Some(m) => format!("{description} Mutation: {}.", m.describe()),
        None => description.to_string(),
    };
    CaseBuilder::new(
        id,
        FILE,
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec,
        &format!("{description} The open is the kit client's open action (payer = the vector signer) for the session challenge of the server it names; the server runs its offline open checks before any co-sign or broadcast."),
        Input::SessionOpen(Box::new(SessionOpenSpec {
            server,
            built_from,
            mutation,
        })),
        expect,
    )
    .requirements(reqs)
}

const LIMIT_IX: &[u8] = &[2, 0x40, 0x0d, 0x03, 0x00];

crate::registry! {
    session_open_v1_advertised_accept => open_case(
        "session-open-v1-advertised-accept",
        open_spec(),
        &[OPEN_VERSION, ACCEPT_LISTED],
        "The session server advertises transactionVersions [0, 1]; the client's open is a version-1 transaction (budget in the header). Servers MUST accept every version they list.",
        session_server(Some(json!([0, 1]))),
        None,
        None,
        Expect::Accept(Pin::Outcome),
    ).build();
    session_open_v1_not_advertised_reject => open_case(
        "session-open-v1-not-advertised-reject",
        admission_spec(),
        &[OPEN_VERSION, REJECT_UNADVERTISED],
        "The session server advertises nothing (so [0]); the open is the same client's version-1 transaction, built for a challenge advertising [0, 1]. Rejected before any instruction is inspected. Pair: session-open-v1-advertised-accept.",
        session_server(None),
        Some(session_server(Some(json!([0, 1])))),
        None,
        Expect::Reject { code: RejectCode::UnsupportedVersion, reason: Some("version 1 is not advertised".into()) },
    ).build();
    session_open_v0_with_v1_advertised_accept => open_case(
        "session-open-v0-with-v1-advertised-accept",
        open_spec(),
        &[OPEN_VERSION, ACCEPT_LISTED],
        "The session server advertises [0, 1]; the open is a version-0 transaction (the client's build for a [0] challenge). Still accepted.",
        session_server(Some(json!([0, 1]))),
        Some(session_server(None)),
        None,
        Expect::Accept(Pin::Outcome),
    ).build();
    session_open_default_v0_accept => open_case(
        "session-open-default-v0-accept",
        open_spec(),
        &[OPEN_VERSION],
        "No transactionVersions and a version-0 open: the default accepted set is [0].",
        session_server(None),
        None,
        None,
        Expect::Accept(Pin::Outcome),
    ).build();
    session_open_legacy_reject => open_case(
        "session-open-legacy-reject",
        legacy_spec(),
        &[NO_LEGACY, OPEN_VERSION],
        "A legacy (unversioned) open carrying the kit's version-0 instructions, against a server advertising [0, 1]: servers MUST reject a legacy message. Pair: session-open-v0-with-v1-advertised-accept.",
        session_server(Some(json!([0, 1]))),
        Some(session_server(None)),
        Some(Mutation::ToFormat { format: MessageFormat::Legacy }),
        Expect::Reject { code: RejectCode::UnsupportedVersion, reason: Some("legacy messages are not supported".into()) },
    )
    .authored(None)
    .build();
    session_open_v1_compute_budget_instruction_reject => open_case(
        "session-open-v1-compute-budget-instruction-reject",
        spec(SESSION, "Transaction Versions", "the transaction MUST NOT contain Compute Budget program instructions. They have no effect under version 1, and servers MUST reject them;"),
        &[V1_NO_BUDGET_IX, V1_REJECT_BUDGET_IX],
        "A version-1 open that also carries a SetComputeUnitLimit instruction. Pair: session-open-v1-advertised-accept.",
        session_server(Some(json!([0, 1]))),
        None,
        Some(Mutation::AddComputeBudget { data: LIMIT_IX }),
        Expect::Reject { code: RejectCode::UnexpectedInstruction, reason: Some("ComputeBudget instruction in a version-1 message".into()) },
    )
    .authored(None)
    .build();
    session_open_v1_missing_compute_unit_limit_reject => open_case(
        "session-open-v1-missing-compute-unit-limit-reject",
        spec(SESSION, "Transaction Versions", "The transaction MUST set computeUnitLimit and loadedAccountsDataSizeLimit; a version-1 transaction that omits either is budgeted zero and cannot execute;"),
        &[V1_LIMITS_SET],
        "A version-1 open whose header omits computeUnitLimit. Pair: session-open-v1-advertised-accept.",
        session_server(Some(json!([0, 1]))),
        None,
        Some(Mutation::V1DropComputeUnitLimit),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: None },
    ).build();
    session_open_v1_priority_fee_over_cap_reject => open_case(
        "session-open-v1-priority-fee-over-cap-reject",
        spec(SESSION, "Transaction Versions", "A server that caps the compute-unit price MUST evaluate priorityFee 1000000 <= maxPriceMicroLamports computeUnitLimit;"),
        &[V1_PRICE_CAP],
        "A version-1 open whose header priority fee is 10000000 lamports: at most 1400000 compute units, so more than 7000000 micro-lamports per unit, over the 5000000 per-unit cap of a client-paid open. Pair: session-open-v1-advertised-accept.",
        session_server(Some(json!([0, 1]))),
        None,
        Some(Mutation::V1PriorityFee { lamports: 10_000_000 }),
        Expect::Reject { code: RejectCode::ComputePriceOverCap, reason: None },
    ).build();

    session_wire_transaction_versions_both_golden => wire(
        "session-wire-transaction-versions-both-golden",
        field_spec(),
        &[ACCEPT_LISTED, OPEN_VERSION, TOPUP_VERSION],
        "Session challenge advertising transactionVersions [0, 1] for client-submitted open and topUp transactions: the SDK's session request schema parses the field and re-encodes it unchanged, as integers. Pins the canonical JSON; an SDK that drops the field tells its clients the server accepts version 0 only.",
        json!([0, 1]),
        golden(),
    ).build();
    session_wire_transaction_versions_v1_only_golden => wire(
        "session-wire-transaction-versions-v1-only-golden",
        field_spec(),
        &[ACCEPT_LISTED, OPEN_VERSION],
        "Session challenge advertising [1] only: round-trips as written, not widened to the [0] default.",
        json!([1]),
        golden(),
    ).build();
    session_wire_transaction_versions_v0_golden => wire(
        "session-wire-transaction-versions-v0-golden",
        field_spec(),
        &[ACCEPT_LISTED],
        "Session challenge advertising [0] explicitly: equal in meaning to the omitted default, but present on the wire, so the canonical bytes keep it.",
        json!([0]),
        golden(),
    ).build();
    session_wire_transaction_versions_legacy_reject => wire(
        "session-wire-transaction-versions-legacy-reject",
        legacy_spec(),
        &[NO_LEGACY],
        "Session challenge advertising [\"legacy\"]: servers MUST NOT advertise legacy; the SDK's session schema refuses the entry.",
        json!(["legacy"]),
        reject("\"legacy\" is not a transactionVersions entry"),
    ).build();
    session_wire_transaction_versions_unknown_reject => wire(
        "session-wire-transaction-versions-unknown-reject",
        field_spec(),
        &[ACCEPT_LISTED],
        "Session challenge advertising [0, 2]: each entry is the integer 0 or 1 (RULINGS T1).",
        json!([0, 2]),
        reject("2 is not a Solana message version"),
    ).build();
    session_wire_transaction_versions_string_entry_reject => wire(
        "session-wire-transaction-versions-string-entry-reject",
        field_spec(),
        &[ACCEPT_LISTED],
        "Session challenge advertising [\"0\"]: entries are integers, never strings (RULINGS T1).",
        json!(["0"]),
        reject("a string entry"),
    ).build();
}
