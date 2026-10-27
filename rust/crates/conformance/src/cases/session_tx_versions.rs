//! MPP session (Solana) transaction versions: the `transactionVersions`
//! method detail of the session challenge, from the pinned draft
//! (`external/mpp-specs-txv1`, solana-foundation/mpp-specs
//! feat/solana-transaction-versions).
//!
//! Three layers: the challenge wire (the session request parsed and
//! re-encoded through the SDK's own session schema, `sessionWire`), the
//! server's version admission of a client-submitted `open`
//! (`sessionOpenVerify`), and the client's version negotiation when it
//! builds that `open` (`sessionOpenBuild`): the highest advertised version
//! its signer can sign, refused before signing when there is none.

use serde_json::{json, Value};

use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role,
    SessionOpenSpec, SpecRef, Suite,
};
use crate::mutate::Mutation;
use crate::realize::session::{Authorized, BuildRecipe, Edit, Server};
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

const BUILD_ADVERTISED: &str = "MPPTX-d180d03a99";

fn build_spec() -> SpecRef {
    spec(
        SESSION,
        "Transaction Versions",
        "Clients MUST build one of the advertised versions and SHOULD build the highest one their signer can produce.",
    )
}

/// The session server of the client build vectors, advertising `versions`
/// (`None`: the field omitted, so `[0]`). The kit server takes `[0]` or
/// `[0, 1]`; a challenge advertising anything else is that server's
/// challenge with `methodDetails.transactionVersions` edited.
fn build_server(versions: Option<&[u8]>, sponsored: bool) -> Server {
    Server {
        sponsored,
        transaction_versions: versions.map(<[u8]>::to_vec),
        ..Server::default()
    }
}

fn build_recipe(server: Server) -> BuildRecipe {
    BuildRecipe {
        server,
        authorized: Authorized::SessionKey,
        edits: vec![],
        client_blockhash: None,
        signer_max_version: None,
    }
}

/// The challenge of `server` with its advertisement replaced by `versions`.
fn advertising(server: Server, versions: Value) -> BuildRecipe {
    BuildRecipe {
        edits: vec![Edit::Set("/methodDetails/transactionVersions", versions)],
        ..build_recipe(server)
    }
}

fn signer_max(recipe: BuildRecipe, version: u8) -> BuildRecipe {
    BuildRecipe {
        signer_max_version: Some(version),
        ..recipe
    }
}

fn build_case(
    id: &str,
    reqs: &[&str],
    description: &str,
    recipe: BuildRecipe,
    expect: Expect,
) -> CaseBuilder {
    let mut notes = Vec::new();
    if !recipe.edits.is_empty() {
        let edits: Vec<String> = recipe.edits.iter().map(Edit::describe).collect();
        notes.push(format!(
            "Challenge edit: {}.",
            edits.join("; ").replace("credential ", "challenge ")
        ));
    }
    if let Some(max) = recipe.signer_max_version {
        notes.push(format!(
            "The signer signs up to version {max} (input.signerMaxTransactionVersion)."
        ));
    }
    let description = std::iter::once(description.to_string())
        .chain(notes)
        .collect::<Vec<_>>()
        .join(" ");
    CaseBuilder::new(
        id,
        FILE,
        Suite::Session,
        Intent::Session,
        Mode::BuildTransaction,
        Role::Client,
        BugType::Defaults,
        build_spec(),
        &description,
        Input::SessionBuild(Box::new(recipe)),
        expect,
    )
    .requirements(reqs)
}

/// What a version build vector pins: the message version, the fee payer,
/// the blockhash and the signature slots (the build judge also compares the
/// message, version-1 header config included, with the kit's build).
fn built() -> Expect {
    Expect::Accept(Pin::ExactBytes(vec![
        "messageVersion",
        "channelId",
        "feePayer",
        "recentBlockhash",
        "signatureSlots",
    ]))
}

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

    // ── client build negotiation ───────────────────────────────────────────
    session_build_v1_advertised => build_case(
        "session-build-v1-advertised",
        &[BUILD_ADVERTISED, V1_LIMITS_SET, V1_NO_BUDGET_IX],
        "The session challenge advertises transactionVersions [0, 1] and the signer is unrestricted: the client builds the highest advertised version, a version-1 open with its compute budget (computeUnitLimit, loadedAccountsDataSizeLimit) in the message header and no ComputeBudget instruction. The kit's session server admits it.",
        build_recipe(build_server(Some(&[0, 1]), false)),
        built(),
    ).build();
    session_build_v1_only_advertised => build_case(
        "session-build-v1-only-advertised",
        &[BUILD_ADVERTISED, V1_LIMITS_SET, V1_NO_BUDGET_IX],
        "The session challenge advertises [1] only: the client MUST build a version-1 open (version 0 is not advertised). The judge's server accepts [0, 1].",
        advertising(build_server(Some(&[0, 1]), false), json!([1])),
        built(),
    ).build();
    session_build_v0_only_advertised => build_case(
        "session-build-v0-only-advertised",
        &[BUILD_ADVERTISED],
        "The session challenge advertises [0] explicitly: the client builds a version-0 open even though it could build version 1.",
        advertising(build_server(None, false), json!([0])),
        built(),
    ).build();
    session_build_absent_builds_v0 => build_case(
        "session-build-absent-builds-v0",
        &[BUILD_ADVERTISED],
        "transactionVersions absent: the server accepts version 0 only, so the client builds a version-0 open. A client that builds version 1 here sends a version the server never advertised.",
        build_recipe(build_server(None, false)),
        built(),
    ).build();
    session_build_v1_sponsored => build_case(
        "session-build-v1-sponsored",
        &[BUILD_ADVERTISED, V1_LIMITS_SET, V1_NO_BUDGET_IX],
        "A fee-sponsored session challenge advertising [0, 1]: a version-1 open whose fee payer (and rentPayer) is feePayerKey, the client signing only as payer; the sponsor slot stays empty.",
        build_recipe(build_server(Some(&[0, 1]), true)),
        built(),
    ).build();
    session_build_signer_v0_picks_v0 => build_case(
        "session-build-signer-v0-picks-v0",
        &[BUILD_ADVERTISED],
        "The session challenge advertises [0, 1] but the signer signs version 0 only (e.g. a hardware wallet): the highest version the signer can produce is 0, and 0 is advertised.",
        signer_max(build_recipe(build_server(Some(&[0, 1]), false)), 0),
        built(),
    ).build();
    session_build_no_buildable_version_reject => build_case(
        "session-build-no-buildable-version-reject",
        &[BUILD_ADVERTISED],
        "The session challenge advertises [1] only and the signer signs version 0 only: no advertised version is buildable, so the client MUST refuse before signing rather than send version 0. Pair: session-build-v1-only-advertised.",
        signer_max(advertising(build_server(Some(&[0, 1]), false), json!([1])), 0),
        Expect::Reject { code: RejectCode::UnsupportedVersion, reason: Some("no advertised version is buildable".into()) },
    ).build();
    session_build_empty_advertisement_reject => build_case(
        "session-build-empty-advertisement-reject",
        &[BUILD_ADVERTISED],
        "transactionVersions [] (present, empty): only an omitted field defaults to [0]. No version is advertised, so the client refuses before signing (RULINGS T2). Pair: session-build-v0-only-advertised.",
        advertising(build_server(None, false), json!([])),
        Expect::Reject { code: RejectCode::UnsupportedVersion, reason: Some("an empty advertisement offers no version".into()) },
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
