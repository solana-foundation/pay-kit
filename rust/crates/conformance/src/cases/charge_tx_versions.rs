//! MPP charge (Solana) transaction versions: the `transactionVersions`
//! method detail, version negotiation in the client builder, and the
//! server's version admission and version-1 (SIMD-0385) rules, from the
//! pinned draft (`external/mpp-specs-txv1`, solana-foundation/mpp-specs
//! feat/solana-transaction-versions).
//!
//! The challenge request is the server's advertisement: verify vectors run
//! against a server that accepts exactly the versions its request lists
//! (`[0]` when the field is absent). Version-1 transactions are the kit's
//! own builds for a request advertising version 1; legacy and lookup-table
//! messages are the kit's version-0 build, recompiled.

use serde_json::{json, Value};

use super::charge::{input, reject, shape, sol_request, spl_request};
use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef, Suite,
};
use crate::keys::{
    CHARGE_RECIPIENT, COMPUTE_BUDGET_PROGRAM, OTHER_MINT, SPLIT_RECIPIENT, SPLIT_RECIPIENT_2,
    X402_OFFER_FEE_PAYER,
};
use crate::mutate::Mutation;
use crate::tx::MessageFormat;

const CHARGE: &str = "mpp-specs-txv1/specs/methods/solana/draft-solana-charge-00.md";
const FILE: &str = "charge-tx-versions.json";

/// The sponsor key of the fee-sponsored requests (the harness holds its seed).
const SERVER_FEE_PAYER: &str = X402_OFFER_FEE_PAYER;

const ACCEPT_LISTED: &str = "MPPTX-102b6dc2a5";
const NO_LEGACY: &str = "MPPTX-5b29a4494f";
const BUILD_ADVERTISED: &str = "MPPTX-d180d03a99";
const NO_ALT: &str = "MPPTX-2855caa59a";
const REJECT_UNADVERTISED: &str = "MPPTX-27a6fd4f3f";
const SIZE_LIMITS: &str = "MPPTX-3f51d8e008";
const PAYLOAD_SIZE: &str = "MPPTX-f8468a31de";
const PAYLOAD_VERSION: &str = "MPPTX-4f1a73dd49";
const V1_LIMITS_SET: &str = "MPPTX-d53a9f42dd";
const V1_NO_BUDGET_IX: &str = "MPPTX-8a036b6610";
const V1_REJECT_BUDGET_IX: &str = "MPPTX-46848f6fce";
const V1_PRICE_CAP: &str = "MPPTX-8a988b0f7a";
const V1_LIMIT_SET_CLIENT: &str = "MPPTX-507629a4fa";
const ONLY_EXPECTED_V0_BUDGET: &str = "MPPTX-c483036092";
const UNEXPECTED_REJECTED: &str = "MPPTX-1a2e7c737e";
const SPL_LEG_MISSING: &str = "MPPTX-96ba338b1e";
const SOL_LEG_MISSING: &str = "MPPTX-6e9ac6c31d";
const SPONSORED_FEE_PAYER: &str = "MPPTX-d5e5d796c6";

fn field_spec() -> SpecRef {
    spec(
        CHARGE,
        "Method Details",
        "Servers MUST accept every version they list, MUST reject any other version, and MUST NOT list 1 unless the enable_tx_v1 feature gate",
    )
}

fn legacy_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "Legacy messages are not supported: servers MUST NOT advertise \"legacy\" and MUST reject a legacy message.",
    )
}

fn build_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "Clients MUST build one of the advertised versions and SHOULD build the highest one their signer can produce.",
    )
}

fn admission_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "Servers MUST reject a transaction whose version is not advertised, or which references an address lookup table, with the malformed-credential problem type, before inspecting any instruction.",
    )
}

fn size_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "A version-0 transaction MUST NOT exceed 1232 serialized bytes; a version-1 transaction MUST NOT exceed 4096 serialized bytes.",
    )
}

fn v1_limits_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "The transaction MUST set computeUnitLimit and loadedAccountsDataSizeLimit; a version-1 transaction that omits either is budgeted zero and cannot execute;",
    )
}

fn v1_budget_ix_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "the transaction MUST NOT contain Compute Budget program instructions. They have no effect under version 1, and servers MUST reject them;",
    )
}

fn v1_price_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "A server that caps the compute-unit price MUST evaluate priorityFee 1000000 <= maxPriceMicroLamports computeUnitLimit;",
    )
}

fn unchanged_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Versions",
        "every other rule in this document applies unchanged.",
    )
}

/// `methodDetails.transactionVersions` set to `versions` (JSON) over `details`.
fn with_versions(versions: Value, details: Value) -> Value {
    let mut md = details;
    md["transactionVersions"] = versions;
    md
}

/// An SPL charge of 1000 whose challenge advertises `versions`.
fn spl(versions: Value) -> Value {
    input(spl_request("1000", with_versions(versions, json!({}))))
}

/// The fee-sponsored SPL charge (sponsor = [`SERVER_FEE_PAYER`]).
fn sponsored(versions: Value) -> Value {
    input(spl_request(
        "1000",
        with_versions(
            versions,
            json!({ "feePayer": true, "feePayerKey": SERVER_FEE_PAYER }),
        ),
    ))
}

/// A charge with three 566-byte memos (the per-memo maximum): about 1.9 KB
/// serialized, over the version-0 limit and well under version 1's.
fn large(versions: Value) -> Value {
    let memo = |c: char| std::iter::repeat_n(c, 566).collect::<String>();
    let mut request = spl_request(
        "1000",
        with_versions(
            versions,
            json!({ "splits": [
                { "recipient": SPLIT_RECIPIENT, "amount": "100", "memo": memo('b') },
                { "recipient": SPLIT_RECIPIENT_2, "amount": "100", "memo": memo('c') }
            ] }),
        ),
    );
    request["externalId"] = json!(memo('a'));
    input(request)
}

fn with_signer_max(mut input: Value, version: u8) -> Value {
    input["signerMaxTransactionVersion"] = json!(version);
    input
}

/// The canonical golden of a charge request carrying `versions`.
fn wire_value(versions: Value) -> Value {
    json!({ "chargeWire": { "value": spl_request("1000", with_versions(versions, json!({}))) } })
}

/// v1 builds pin the fee payer, the transfers and the header compute limit
/// (the client MUST set it), and that no ComputeBudget program appears.
fn v1_shape() -> Pin {
    shape(true, false, true, &[COMPUTE_BUDGET_PROGRAM])
}

fn wire_case(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        FILE,
        Suite::Charge,
        Intent::Charge,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        spec,
        description,
        Input::Static(input),
        expect,
    )
    .requirements(reqs)
}

fn build(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> CaseBuilder {
    CaseBuilder::new(
        id,
        FILE,
        Suite::Charge,
        Intent::Charge,
        Mode::BuildTransaction,
        Role::Client,
        BugType::Defaults,
        spec,
        description,
        Input::Static(input),
        expect,
    )
    .requirements(reqs)
}

/// A verify case: the kit builds from `built_from` (default: `base`), the
/// optional operator rewrites it, and the server verifies against `base`.
/// Accepts may carry an operator (a valid rewrite); a generated reject takes
/// its code from the operator table (`realize::check_pairing`).
#[allow(clippy::too_many_arguments)]
fn verify(
    id: &str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    base: Value,
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
        Suite::Charge,
        Intent::Charge,
        Mode::VerifyTransaction,
        Role::Server,
        bug,
        spec,
        &description,
        Input::ChargeTransaction {
            base,
            mutation,
            built_from,
        },
        expect,
    )
    .requirements(reqs)
}

fn from_table(mutation: &Mutation) -> Expect {
    Expect::Reject {
        code: mutation
            .expected(Suite::Charge)
            .unwrap_or_else(|| panic!("{mutation:?} has no charge reject code")),
        reason: None,
    }
}

/// A version-1 policy mutation (same operator, same code as on version 0).
fn v1_policy(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    base: Value,
    mutation: Mutation,
) -> CaseBuilder {
    let expect = from_table(&mutation);
    verify(
        id,
        BugType::Settlement,
        spec,
        reqs,
        &format!("{description} The pinned transaction is the kit's version-1 build (compute budget in the header), so the rule is checked independently of the message version."),
        base,
        None,
        Some(mutation),
        expect,
    )
}

const LIMIT_IX: &[u8] = &[2, 0x40, 0x0d, 0x03, 0x00];

crate::registry! {
    // ── wire: methodDetails.transactionVersions ────────────────────────────
    charge_wire_transaction_versions_both_golden => wire_case(
        "charge-wire-transaction-versions-both-golden",
        field_spec(),
        &[ACCEPT_LISTED],
        "methodDetails.transactionVersions [0, 1]: an array of the integers 0 and 1 (the Wallet Standard vocabulary without \"legacy\"). The SDK's charge-request type parses it and re-encodes it unchanged, as integers; pins the canonical JSON.",
        wire_value(json!([0, 1])),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    ).build();
    charge_wire_transaction_versions_v1_only_golden => wire_case(
        "charge-wire-transaction-versions-v1-only-golden",
        field_spec(),
        &[ACCEPT_LISTED],
        "methodDetails.transactionVersions [1]: a version-1-only server. The field round-trips through the SDK's charge-request type as written (not widened to the [0] default).",
        wire_value(json!([1])),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    ).build();
    charge_wire_transaction_versions_legacy_reject => wire_case(
        "charge-wire-transaction-versions-legacy-reject",
        legacy_spec(),
        &[NO_LEGACY],
        "methodDetails.transactionVersions [\"legacy\"]: servers MUST NOT advertise legacy, so the value is outside the field's vocabulary and the SDK's charge-request type refuses it.",
        wire_value(json!(["legacy"])),
        reject(RejectCode::InvalidPayload, "\"legacy\" is not a transactionVersions entry"),
    ).build();
    charge_wire_transaction_versions_unknown_reject => wire_case(
        "charge-wire-transaction-versions-unknown-reject",
        field_spec(),
        &[ACCEPT_LISTED],
        "methodDetails.transactionVersions [0, 2]: each entry is the integer 0 or 1; version 2 does not exist, so no server can accept it and the request is refused (RULINGS T1).",
        wire_value(json!([0, 2])),
        reject(RejectCode::InvalidPayload, "2 is not a Solana message version"),
    ).build();
    charge_wire_transaction_versions_string_entry_reject => wire_case(
        "charge-wire-transaction-versions-string-entry-reject",
        field_spec(),
        &[ACCEPT_LISTED],
        "methodDetails.transactionVersions [\"1\"]: entries are integers, never strings (RULINGS T1).",
        wire_value(json!(["1"])),
        reject(RejectCode::InvalidPayload, "a string entry"),
    ).build();
    charge_wire_transaction_versions_not_array_reject => wire_case(
        "charge-wire-transaction-versions-not-array-reject",
        field_spec(),
        &[ACCEPT_LISTED],
        "methodDetails.transactionVersions 1: the field is an array, never a bare integer (RULINGS T1).",
        wire_value(json!(1)),
        reject(RejectCode::InvalidPayload, "not an array"),
    ).build();

    // ── client build negotiation ───────────────────────────────────────────
    charge_build_v1_advertised => build(
        "charge-build-v1-advertised",
        build_spec(),
        &[BUILD_ADVERTISED, V1_LIMIT_SET_CLIENT],
        "The challenge advertises [0, 1] and the signer is unrestricted: the client builds the highest advertised version, a version-1 message with the compute budget (computeUnitLimit set) in its header and no ComputeBudget instruction. The build judge compares the message version and header config with the kit's build.",
        spl(json!([0, 1])),
        Expect::Accept(v1_shape()),
    ).build();
    charge_build_v1_only_advertised => build(
        "charge-build-v1-only-advertised",
        build_spec(),
        &[BUILD_ADVERTISED, V1_LIMIT_SET_CLIENT],
        "The challenge advertises [1] only: the client MUST build version 1 (a version-0 build is not one of the advertised versions).",
        spl(json!([1])),
        Expect::Accept(v1_shape()),
    ).build();
    charge_build_absent_builds_v0 => build(
        "charge-build-absent-builds-v0",
        build_spec(),
        &[BUILD_ADVERTISED],
        "transactionVersions absent: it defaults to [0], so the client builds a version-0 message with the ComputeBudget prefix. A client that builds version 1 here sends a version the server never advertised.",
        input(spl_request("1000", json!({}))),
        Expect::Accept(shape(true, false, true, &[])),
    ).build();
    charge_build_v0_only_advertised => build(
        "charge-build-v0-only-advertised",
        build_spec(),
        &[BUILD_ADVERTISED],
        "The challenge advertises [0]: the client builds version 0 even though it could build version 1.",
        spl(json!([0])),
        Expect::Accept(shape(true, false, true, &[])),
    ).build();
    charge_build_signer_v0_picks_v0 => build(
        "charge-build-signer-v0-picks-v0",
        build_spec(),
        &[BUILD_ADVERTISED],
        "The challenge advertises [0, 1] but the signer signs version 0 only (input.signerMaxTransactionVersion = 0, e.g. a hardware wallet): the highest version the signer can produce is 0, and 0 is advertised.",
        with_signer_max(spl(json!([0, 1])), 0),
        Expect::Accept(shape(true, false, true, &[])),
    ).build();
    charge_build_no_buildable_version_reject => build(
        "charge-build-no-buildable-version-reject",
        build_spec(),
        &[BUILD_ADVERTISED],
        "The challenge advertises [1] only and the signer signs version 0 only: no advertised version is buildable, so the client MUST refuse up front rather than send version 0 (or fail at the device).",
        with_signer_max(spl(json!([1])), 0),
        reject(RejectCode::UnsupportedVersion, "no advertised version is buildable"),
    ).build();
    charge_build_empty_advertisement_reject => build(
        "charge-build-empty-advertisement-reject",
        build_spec(),
        &[BUILD_ADVERTISED],
        "transactionVersions [] (present, empty): only an omitted field defaults to [0]. The client MUST build one of the advertised versions and none is advertised, so it refuses (RULINGS T2).",
        spl(json!([])),
        reject(RejectCode::UnsupportedVersion, "an empty advertisement offers no version"),
    )
    .authored(None)
    .build();
    charge_build_duplicate_advertisement => build(
        "charge-build-duplicate-advertisement",
        build_spec(),
        &[BUILD_ADVERTISED],
        "transactionVersions [1, 1]: a repeated entry names the same version; the advertised set is {1} and the client builds version 1 (RULINGS T1).",
        spl(json!([1, 1])),
        Expect::Accept(v1_shape()),
    ).build();
    charge_build_v1_sponsored => build(
        "charge-build-v1-sponsored",
        spec(CHARGE, "Transaction Payload — Pull Mode", "When feePayer is true, the transaction MUST set the server's feePayerKey as fee payer, and the client signs only as transfer authority; the server adds the fee payer signature before broadcasting (see {{fee-sponsorship}})."),
        &[BUILD_ADVERTISED, SPONSORED_FEE_PAYER],
        "Fee-sponsored challenge advertising [0, 1]: a version-1 message whose fee payer is feePayerKey, the client signing only as transfer authority (the sponsor slot stays empty; the build judge checks every slot).",
        sponsored(json!([0, 1])),
        Expect::Accept(v1_shape()),
    ).build();
    charge_build_v1_sol => build(
        "charge-build-v1-sol",
        build_spec(),
        &[BUILD_ADVERTISED],
        "Native SOL charge advertising [0, 1]: a version-1 message carrying the System Program transfer, budget in the header.",
        input(sol_request("1000000", json!({ "transactionVersions": [0, 1] }))),
        Expect::Accept(v1_shape()),
    ).build();
    charge_build_v1_large_memos => build(
        "charge-build-v1-large-memos",
        size_spec(),
        &[BUILD_ADVERTISED, SIZE_LIMITS],
        "Three 566-byte memos (externalId and two split memos) under [0, 1]: about 1.9 KB, which fits version 1's 4096-byte limit but not version 0's 1232. The client builds version 1.",
        large(json!([0, 1])),
        Expect::Accept(shape(true, true, true, &[COMPUTE_BUDGET_PROGRAM])),
    ).build();

    // ── server: version admission ──────────────────────────────────────────
    charge_verify_v1_advertised_accept => verify(
        "charge-verify-v1-advertised-accept",
        BugType::Wire,
        field_spec(),
        &[ACCEPT_LISTED, PAYLOAD_VERSION],
        "The challenge advertises [0, 1] and the credential is the kit's version-1 build: servers MUST accept every version they list.",
        spl(json!([0, 1])),
        None,
        None,
        Expect::Accept(v1_shape()),
    ).build();
    charge_verify_v1_only_advertised_accept => verify(
        "charge-verify-v1-only-advertised-accept",
        BugType::Wire,
        field_spec(),
        &[ACCEPT_LISTED, PAYLOAD_VERSION],
        "The challenge advertises [1] only and the credential is a version-1 build.",
        spl(json!([1])),
        None,
        None,
        Expect::Accept(v1_shape()),
    ).build();
    charge_verify_v1_not_advertised_reject => verify(
        "charge-verify-v1-not-advertised-reject",
        BugType::AuthBypass,
        admission_spec(),
        &[REJECT_UNADVERTISED, ACCEPT_LISTED, PAYLOAD_VERSION],
        "The challenge carries no transactionVersions (so [0]) and the credential is a version-1 transaction (the kit's build for the same charge advertising [0, 1]). Rejected before any instruction is inspected: the transaction is otherwise valid.",
        input(spl_request("1000", json!({}))),
        Some(spl(json!([0, 1]))),
        None,
        reject(RejectCode::UnsupportedVersion, "version 1 is not advertised"),
    ).build();
    charge_verify_v1_v0_only_reject => verify(
        "charge-verify-v1-v0-only-reject",
        BugType::AuthBypass,
        admission_spec(),
        &[REJECT_UNADVERTISED, ACCEPT_LISTED],
        "The challenge advertises [0] explicitly and the credential is version 1.",
        spl(json!([0])),
        Some(spl(json!([0, 1]))),
        None,
        reject(RejectCode::UnsupportedVersion, "version 1 is not advertised"),
    ).build();
    charge_verify_v0_to_v1_only_reject => verify(
        "charge-verify-v0-to-v1-only-reject",
        BugType::AuthBypass,
        admission_spec(),
        &[REJECT_UNADVERTISED, ACCEPT_LISTED],
        "The challenge advertises [1] only and the credential is a valid version-0 transaction (the kit's build for the same charge without the field). MUST reject any other version: version 0 is not implied.",
        spl(json!([1])),
        Some(input(spl_request("1000", json!({})))),
        None,
        reject(RejectCode::UnsupportedVersion, "version 0 is not advertised"),
    ).build();
    charge_verify_v0_with_v1_advertised_accept => verify(
        "charge-verify-v0-with-v1-advertised-accept",
        BugType::Wire,
        field_spec(),
        &[ACCEPT_LISTED],
        "The challenge advertises [0, 1] and the credential is a version-0 transaction: still accepted (positive control for the version-1-only and legacy rejects).",
        spl(json!([0, 1])),
        Some(input(spl_request("1000", json!({})))),
        None,
        Expect::Accept(shape(true, false, true, &[])),
    ).build();
    charge_verify_legacy_reject => verify(
        "charge-verify-legacy-reject",
        BugType::Wire,
        legacy_spec(),
        &[NO_LEGACY, REJECT_UNADVERTISED],
        "A legacy (unversioned) message with the kit's version-0 instructions, against a challenge advertising [0, 1]: servers MUST reject a legacy message. Pair: charge-verify-v0-with-v1-advertised-accept.",
        spl(json!([0, 1])),
        Some(input(spl_request("1000", json!({})))),
        Some(Mutation::ToFormat { format: MessageFormat::Legacy }),
        reject(RejectCode::UnsupportedVersion, "legacy messages are not supported"),
    )
    .authored(None)
    .build();
    charge_verify_legacy_default_reject => verify(
        "charge-verify-legacy-default-reject",
        BugType::Wire,
        legacy_spec(),
        &[NO_LEGACY],
        "A legacy message against a challenge with no transactionVersions: the default [0] does not admit legacy either. Pair: charge-verify-default-v0-accept.",
        input(spl_request("1000", json!({}))),
        None,
        Some(Mutation::ToFormat { format: MessageFormat::Legacy }),
        reject(RejectCode::UnsupportedVersion, "legacy messages are not supported"),
    )
    .authored(None)
    .build();
    charge_verify_default_v0_accept => verify(
        "charge-verify-default-v0-accept",
        BugType::Wire,
        field_spec(),
        &[ACCEPT_LISTED],
        "No transactionVersions and a version-0 credential: the default accepted set is [0].",
        input(spl_request("1000", json!({}))),
        None,
        None,
        Expect::Accept(shape(true, false, true, &[])),
    ).build();
    charge_verify_lookup_table_reject => verify(
        "charge-verify-lookup-table-reject",
        BugType::AuthBypass,
        admission_spec(),
        &[REJECT_UNADVERTISED, NO_ALT],
        "A version-0 transaction whose recipient ATA is resolved through an address lookup table: the server cannot see the account in the static keys and MUST reject before inspecting any instruction. Pair: charge-verify-default-v0-accept.",
        input(spl_request("1000", json!({}))),
        None,
        Some(Mutation::AddLookupTable),
        from_table(&Mutation::AddLookupTable),
    ).build();
    charge_verify_v0_oversize_reject => verify(
        "charge-verify-v0-oversize-reject",
        BugType::Wire,
        size_spec(),
        &[SIZE_LIMITS, PAYLOAD_SIZE],
        "The kit's version-1 build of the three-566-byte-memo charge, recompiled as version 0 (budget back into instructions): about 1.9 KB, over the version-0 limit of 1232 bytes, against a challenge advertising [0, 1]. Pair: charge-verify-v1-large-memos-accept.",
        large(json!([0, 1])),
        None,
        Some(Mutation::ToFormat { format: MessageFormat::V0 }),
        reject(RejectCode::InvalidPayload, "a version-0 transaction over 1232 bytes"),
    )
    .authored(None)
    .build();
    charge_verify_v1_large_memos_accept => verify(
        "charge-verify-v1-large-memos-accept",
        BugType::Wire,
        size_spec(),
        &[SIZE_LIMITS, PAYLOAD_SIZE],
        "The same 1.9 KB charge as version 1: within the 4096-byte version-1 limit, accepted.",
        large(json!([0, 1])),
        None,
        None,
        Expect::Accept(shape(true, true, true, &[COMPUTE_BUDGET_PROGRAM])),
    ).build();

    // ── server: version-1 compute budget ───────────────────────────────────
    charge_verify_v1_compute_budget_instruction_reject => verify(
        "charge-verify-v1-compute-budget-instruction-reject",
        BugType::Settlement,
        v1_budget_ix_spec(),
        &[V1_NO_BUDGET_IX, V1_REJECT_BUDGET_IX, ONLY_EXPECTED_V0_BUDGET, UNEXPECTED_REJECTED],
        "A version-1 transaction that also carries a SetComputeUnitLimit instruction: ComputeBudget instructions have no effect under version 1, so a verifier that bounds them bounds nothing, and they MUST be rejected. Pair: charge-verify-v1-advertised-accept.",
        spl(json!([0, 1])),
        None,
        Some(Mutation::AddComputeBudget { data: LIMIT_IX }),
        from_table(&Mutation::AddComputeBudget { data: LIMIT_IX }),
    ).build();
    charge_verify_v1_missing_compute_unit_limit_reject => verify(
        "charge-verify-v1-missing-compute-unit-limit-reject",
        BugType::Settlement,
        v1_limits_spec(),
        &[V1_LIMITS_SET, V1_LIMIT_SET_CLIENT],
        "A version-1 header without computeUnitLimit: budgeted zero compute units, it cannot execute after the fee is charged. Pair: charge-verify-v1-advertised-accept.",
        spl(json!([0, 1])),
        None,
        Some(Mutation::V1DropComputeUnitLimit),
        from_table(&Mutation::V1DropComputeUnitLimit),
    ).build();
    charge_verify_v1_missing_loaded_data_limit_reject => verify(
        "charge-verify-v1-missing-loaded-data-limit-reject",
        BugType::Settlement,
        v1_limits_spec(),
        &[V1_LIMITS_SET],
        "A version-1 header without loadedAccountsDataSizeLimit: budgeted zero bytes of account data, it fails at load time after the fee is charged. Pair: charge-verify-v1-advertised-accept.",
        spl(json!([0, 1])),
        None,
        Some(Mutation::V1DropLoadedAccountsDataSizeLimit),
        from_table(&Mutation::V1DropLoadedAccountsDataSizeLimit),
    ).build();
    charge_verify_v1_priority_fee_at_cap_accept => verify(
        "charge-verify-v1-priority-fee-at-cap-accept",
        BugType::Settlement,
        v1_price_spec(),
        &[V1_PRICE_CAP],
        "Client-paid charge, version-1 header computeUnitLimit 200000 with priorityFee 1000000 lamports: 1000000 * 1000000 = 5000000 * 200000, exactly the 5000000 micro-lamport per-unit cap. Accepted (the cap is inclusive).",
        spl(json!([0, 1])),
        None,
        Some(Mutation::V1PriorityFee { lamports: 1_000_000 }),
        Expect::Accept(v1_shape()),
    ).build();
    charge_verify_v1_priority_fee_over_cap_reject => verify(
        "charge-verify-v1-priority-fee-over-cap-reject",
        BugType::Settlement,
        v1_price_spec(),
        &[V1_PRICE_CAP],
        "Client-paid charge, priorityFee 1000001 lamports over a 200000 unit limit: one lamport above priorityFee * 1000000 <= 5000000 * 200000. The total fee is normalised per unit, not compared with the per-unit cap directly.",
        spl(json!([0, 1])),
        None,
        Some(Mutation::V1PriorityFee { lamports: 1_000_001 }),
        from_table(&Mutation::V1PriorityFee { lamports: 1_000_001 }),
    ).build();
    charge_verify_v1_sponsored_priority_fee_at_cap_accept => verify(
        "charge-verify-v1-sponsored-priority-fee-at-cap-accept",
        BugType::Settlement,
        v1_price_spec(),
        &[V1_PRICE_CAP, SPONSORED_FEE_PAYER],
        "Fee-sponsored charge (the sponsor caps the price at 10000 micro-lamports per unit), version-1 priorityFee 2000 lamports over 200000 units: 2000 * 1000000 = 10000 * 200000. Accepted.",
        sponsored(json!([0, 1])),
        None,
        Some(Mutation::V1PriorityFee { lamports: 2_000 }),
        Expect::Accept(v1_shape()),
    ).build();
    charge_verify_v1_sponsored_priority_fee_over_cap_reject => verify(
        "charge-verify-v1-sponsored-priority-fee-over-cap-reject",
        BugType::Settlement,
        v1_price_spec(),
        &[V1_PRICE_CAP, SPONSORED_FEE_PAYER],
        "Fee-sponsored charge, priorityFee 2001 lamports over 200000 units: above the sponsor's 10000 micro-lamport per-unit cap. A sponsor that compares the lamport total with the per-unit cap (2001 < 10000) pays the client's priority fee.",
        sponsored(json!([0, 1])),
        None,
        Some(Mutation::V1PriorityFee { lamports: 2_001 }),
        from_table(&Mutation::V1PriorityFee { lamports: 2_001 }),
    ).build();
    charge_verify_v1_reduced_limit_price_reject => verify(
        "charge-verify-v1-reduced-limit-price-reject",
        BugType::Settlement,
        v1_price_spec(),
        &[V1_PRICE_CAP],
        "Fee-sponsored charge whose version-1 header lowers computeUnitLimit to 50 while keeping the 1-lamport priority fee: 1 * 1000000 > 10000 * 50, i.e. 20000 micro-lamports per unit. The total fee is under any per-unit number; only normalising by the declared limit exposes it.",
        sponsored(json!([0, 1])),
        None,
        Some(Mutation::V1ComputeUnitLimit { limit: 50 }),
        reject(RejectCode::ComputePriceOverCap, "1 lamport over 50 units is 20000 micro-lamports per unit"),
    )
    .authored(None)
    .build();

    // ── server: the same policy on version 1 ───────────────────────────────
    charge_verify_v1_underpay_reject => v1_policy(
        "charge-verify-v1-underpay-reject",
        unchanged_spec(),
        &[SPL_LEG_MISSING],
        "Version-1 transfer one base unit short of the charge.",
        spl(json!([0, 1])),
        Mutation::BumpAmount { transfer: 0, delta: -1 },
    ).build();
    charge_verify_v1_wrong_recipient_reject => v1_policy(
        "charge-verify-v1-wrong-recipient-reject",
        unchanged_spec(),
        &[SPL_LEG_MISSING],
        "Version-1 transfer redirected to another owner's ATA.",
        spl(json!([0, 1])),
        Mutation::SwapRecipient { transfer: 0, owner: SPLIT_RECIPIENT },
    ).build();
    charge_verify_v1_wrong_mint_reject => v1_policy(
        "charge-verify-v1-wrong-mint-reject",
        unchanged_spec(),
        &[SPL_LEG_MISSING],
        "Version-1 transfer paid in another mint.",
        spl(json!([0, 1])),
        Mutation::WrongMint { transfer: 0, mint: OTHER_MINT, source_owner: crate::keys::CLIENT, destination_owner: CHARGE_RECIPIENT },
    ).build();
    charge_verify_v1_sol_underpay_reject => v1_policy(
        "charge-verify-v1-sol-underpay-reject",
        unchanged_spec(),
        &[SOL_LEG_MISSING],
        "Native SOL version-1 transfer one lamport short.",
        input(sol_request("1000000", json!({ "transactionVersions": [0, 1] }))),
        Mutation::BumpAmount { transfer: 0, delta: -1 },
    ).build();
    charge_verify_v1_unexpected_instruction_reject => v1_policy(
        "charge-verify-v1-unexpected-instruction-reject",
        unchanged_spec(),
        &[UNEXPECTED_REJECTED, ONLY_EXPECTED_V0_BUDGET],
        "Version-1 transaction with an extra instruction of an unrelated program after the transfer.",
        spl(json!([0, 1])),
        Mutation::AddProgramInstruction { program: SPLIT_RECIPIENT_2, data: &[1, 2, 3] },
    ).build();
    charge_verify_v1_sponsor_as_authority_reject => v1_policy(
        "charge-verify-v1-sponsor-as-authority-reject",
        unchanged_spec(),
        &[SPONSORED_FEE_PAYER],
        "Fee-sponsored version-1 transaction whose transfer authority is the sponsor: the client signs only as transfer authority, so a sponsor named as the authority would pay the charge.",
        sponsored(json!([0, 1])),
        Mutation::FeePayerAsAuthority { transfer: 0 },
    ).build();
}
