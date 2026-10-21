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
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef, Suite,
};

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

crate::registry! {
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
