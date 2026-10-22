//! x402 `exact` (SVM) transaction versions, scheme_exact_svm.md §1.5 from
//! the pinned draft (`external/x402-txv1`, x402-foundation/x402 PR 3473):
//! the `extra.transactionVersions` advertisement, the client's
//! intersect-and-build-highest rule, the sponsor's own accepted set, and the
//! version-1 static layout and header compute caps.
//!
//! Verify vectors carry the §3.1 static layout as a version-0 or version-1
//! message (`X402HeaderSpec::tx_format`); `input.x402ServerTransactionVersions`
//! is the sponsor's accepted set, which the route advertises and the client
//! echoes in `accepted`.

use serde_json::{json, Value};

use super::x402_exact::{build_input, devnet_route, header, offer, reject, verify_case, V2_SHAPE};
use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef, Suite,
    X402HeaderSpec,
};
use crate::keys::{CLIENT, DEVNET_CAIP2, MINT, OTHER_MINT, X402_OTHER_PAY_TO, X402_PAY_TO};
use crate::mutate::Mutation;
use crate::tx::MessageFormat;

const SVM: &str = "x402-txv1/specs/schemes/exact/scheme_exact_svm.md";
const FILE: &str = "x402-tx-versions.json";

const PAYLOAD_VERSION: &str = "X402TX-10b3fe2ef3";
const SERVER_COPIES: &str = "X402TX-f39a33ff74";
const NO_LEGACY_BUILD: &str = "X402TX-77742f428c";
const INTERSECT_HIGHEST: &str = "X402TX-61c735c7a9";
const EMPTY_FAILS: &str = "X402TX-2909c4b4ec";
const SPONSOR_SET: &str = "X402TX-24efe57db3";
const SIZE_LIMITS: &str = "X402TX-dc7b0f3305";
const V1_BUDGET: &str = "X402TX-644919eb3b";
const V1_CAPS: &str = "X402TX-eb681e1701";
const V1_NO_BUDGET_IX: &str = "X402TX-936b492daa";
const V1_LAYOUT: &str = "X402TX-d188782061";
const FAST_PATH_PRICE: &str = "X402TX-2ad7a3f326";
const EXACTLY_ONE: &str = "X402TX-ee90546220";
const NOT_LESS: &str = "X402TX-516a2d7b57";
const FEE_PAYER_ISOLATION: &str = "X402TX-dd5384e0fe";
const SELF_SPEND: &str = "X402TX-bc031b7add";
const TRANSFER_MATCH: &str = "X402TX-f9c2b66234";

const BOTH: &[u8] = &[0, 1];

fn versions_spec() -> SpecRef {
    spec(
        SVM,
        "1.5 Transaction Versions (MUST)",
        "The client MUST intersect the advertised versions ([0] when the field is absent) with the versions it and its signer support, then build the highest version in that intersection.",
    )
}

fn empty_spec() -> SpecRef {
    spec(
        SVM,
        "1.5 Transaction Versions (MUST)",
        "It MUST fail with unsupported_transaction_version when the intersection is empty.",
    )
}

fn sponsor_spec() -> SpecRef {
    spec(
        SVM,
        "1.5 Transaction Versions (MUST)",
        "The sponsor MUST reject a message whose version is outside the set it accepts, before inspecting any instruction, with unsupported_transaction_version.",
    )
}

fn copy_spec() -> SpecRef {
    spec(
        SVM,
        "1.5 Transaction Versions (MUST)",
        "The facilitator advertises the versions it accepts as extra.transactionVersions in /supported, and the server MUST copy that value into PaymentRequirements.extra.transactionVersions.",
    )
}

fn size_spec() -> SpecRef {
    spec(
        SVM,
        "1.5 Transaction Versions (MUST)",
        "A legacy or version-0 transaction MUST NOT exceed 1232 serialized bytes; a version-1 transaction MUST NOT exceed 4096 serialized bytes.",
    )
}

fn caps_spec() -> SpecRef {
    spec(
        SVM,
        "2.2.1 Compute Budget Controls (SHOULD)",
        "In a version-1 transaction the same caps apply to the message TransactionConfig instead: computeUnitLimit MUST be present and MUST NOT exceed the configured maximum, loadedAccountsDataSizeLimit MUST be present, and priorityFee (total lamports) MUST satisfy priorityFee 1000000 <= maxPriorityFeeMicroLamports computeUnitLimit.",
    )
}

fn layout_spec() -> SpecRef {
    spec(
        SVM,
        "3.1 Path 1 — Static Layout Verification (standard wallets)",
        "A version-1 transaction MUST contain 1 to 5 instructions in this order:",
    )
}

fn v1_offer(versions: Value) -> Value {
    let mut offer = offer(DEVNET_CAIP2, "1000", MINT, 300);
    offer["extra"]["transactionVersions"] = versions;
    offer
}

fn build_with(offer: Value, extra: Value) -> Value {
    build_input(Some(2), offer, MINT, extra)
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
        Suite::X402Exact,
        Intent::X402Exact,
        Mode::BuildTransaction,
        Role::Client,
        BugType::Defaults,
        spec,
        &format!("{description} The build judge verifies the header with a Rust sponsor accepting the offer's versions and compares the message version and header config with the kit's build."),
        Input::Static(input),
        expect,
    )
    .requirements(reqs)
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
        Suite::X402Exact,
        Intent::X402Exact,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        spec,
        description,
        Input::Static(json!({ "x402Wire": { "value": v1_offer(versions) } })),
        expect,
    )
    .requirements(reqs)
}

/// The static layout as `format` against a sponsor accepting `server`
/// (`None`: the default `[0]`), optionally mutated.
fn layout(
    format: MessageFormat,
    server: Option<&'static [u8]>,
    mutation: Option<Mutation>,
) -> X402HeaderSpec {
    X402HeaderSpec {
        tx_format: format,
        server_transaction_versions: server,
        mutation,
        ..header(devnet_route())
    }
}

fn verify(
    id: &str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    header: X402HeaderSpec,
    expect: Expect,
) -> CaseBuilder {
    verify_case(id, FILE, bug, spec, reqs, description, header, expect)
}

fn from_table(mutation: &Mutation) -> Expect {
    Expect::Reject {
        code: mutation
            .expected(Suite::X402Exact)
            .unwrap_or_else(|| panic!("{mutation:?} has no x402 reject code")),
        reason: None,
    }
}

/// A version-1 policy mutation against a `[0, 1]` sponsor: same operator,
/// same code as the version-0 case of the same rule.
fn v1_policy(
    id: &str,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    mutation: Mutation,
) -> CaseBuilder {
    let expect = from_table(&mutation);
    verify(
        id,
        BugType::Settlement,
        spec,
        reqs,
        &format!("{description} The transaction is the version-1 static layout (budget in the header, no ComputeBudget instructions), so the rule is checked independently of the message version."),
        layout(MessageFormat::V1, Some(BOTH), Some(mutation)),
        expect,
    )
}

const LIMIT_IX: &[u8] = &[2, 0x40, 0x0d, 0x03, 0x00];

crate::registry! {
    // ── wire: extra.transactionVersions ────────────────────────────────────
    x402_wire_transaction_versions_golden => wire(
        "x402-wire-transaction-versions-golden",
        copy_spec(),
        &[SERVER_COPIES],
        "PaymentRequirements whose extra.transactionVersions is [0, 1] (copied from the facilitator's /supported): the SDK's requirements type parses it and re-encodes it unchanged, as integers. An SDK that drops the field tells its clients the sponsor accepts version 0 only.",
        json!([0, 1]),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    ).build();
    x402_wire_transaction_versions_v1_only_golden => wire(
        "x402-wire-transaction-versions-v1-only-golden",
        copy_spec(),
        &[SERVER_COPIES],
        "extra.transactionVersions [1]: round-trips as written.",
        json!([1]),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    ).build();

    // ── client build negotiation ───────────────────────────────────────────
    x402_build_v1_advertised => build(
        "x402-build-v1-advertised",
        versions_spec(),
        &[INTERSECT_HIGHEST, PAYLOAD_VERSION],
        "The offer advertises [0, 1] and the client and its signer support both: the client builds the highest version in the intersection, a version-1 message in the §3.1 version-1 layout (TransferChecked, Memo; budget in the header), and echoes extra.transactionVersions in accepted.",
        build_with(v1_offer(json!([0, 1])), json!({})),
        Expect::Accept(Pin::Envelope(V2_SHAPE.to_vec())),
    ).build();
    x402_build_absent_builds_v0 => build(
        "x402-build-absent-builds-v0",
        versions_spec(),
        &[INTERSECT_HIGHEST, PAYLOAD_VERSION],
        "extra.transactionVersions absent: the advertised set is [0], so the client builds version 0 with the ComputeBudget prefix. A client that builds version 1 here sends a version the sponsor never accepted.",
        build_with(offer(DEVNET_CAIP2, "1000", MINT, 300), json!({})),
        Expect::Accept(Pin::Envelope(V2_SHAPE.to_vec())),
    ).build();
    x402_build_v0_advertised => build(
        "x402-build-v0-advertised",
        versions_spec(),
        &[INTERSECT_HIGHEST],
        "extra.transactionVersions [0]: the intersection is {0}; the client builds version 0 even though it can build version 1.",
        build_with(v1_offer(json!([0])), json!({})),
        Expect::Accept(Pin::Envelope(V2_SHAPE.to_vec())),
    ).build();
    x402_build_signer_v0_picks_v0 => build(
        "x402-build-signer-v0-picks-v0",
        versions_spec(),
        &[INTERSECT_HIGHEST],
        "The offer advertises [0, 1] but the signer signs version 0 only (input.signerMaxTransactionVersion = 0): the intersection is {0}.",
        build_with(v1_offer(json!([0, 1])), json!({ "signerMaxTransactionVersion": 0 })),
        Expect::Accept(Pin::Envelope(V2_SHAPE.to_vec())),
    ).build();
    x402_build_duplicate_advertisement => build(
        "x402-build-duplicate-advertisement",
        versions_spec(),
        &[INTERSECT_HIGHEST],
        "extra.transactionVersions [1, 0, 1]: a repeated entry names the same version; the intersection is {0, 1} and the client builds version 1 (RULINGS T1).",
        build_with(v1_offer(json!([1, 0, 1])), json!({})),
        Expect::Accept(Pin::Envelope(V2_SHAPE.to_vec())),
    ).build();
    x402_build_no_intersection_reject => build(
        "x402-build-no-intersection-reject",
        empty_spec(),
        &[EMPTY_FAILS, INTERSECT_HIGHEST],
        "The offer advertises [1] only and the signer signs version 0 only: the intersection is empty and the client MUST fail with unsupported_transaction_version instead of building version 0.",
        build_with(v1_offer(json!([1])), json!({ "signerMaxTransactionVersion": 0 })),
        reject(RejectCode::UnsupportedVersion, "unsupported_transaction_version: empty intersection"),
    ).build();
    x402_build_empty_advertisement_reject => build(
        "x402-build-empty-advertisement-reject",
        empty_spec(),
        &[EMPTY_FAILS, INTERSECT_HIGHEST],
        "extra.transactionVersions [] (present, empty): only an absent field means [0]. The intersection is empty, so the client MUST fail with unsupported_transaction_version (RULINGS T2).",
        build_with(v1_offer(json!([])), json!({})),
        reject(RejectCode::UnsupportedVersion, "unsupported_transaction_version: empty advertisement"),
    )
    .authored(None)
    .build();
    x402_build_legacy_only_reject => build(
        "x402-build-legacy-only-reject",
        spec(SVM, "1.5 Transaction Versions (MUST)", "They are never advertised in extra.transactionVersions and clients MUST NOT build them."),
        &[NO_LEGACY_BUILD, EMPTY_FAILS],
        "extra.transactionVersions [\"legacy\"]: clients MUST NOT build legacy, so nothing in the advertisement is buildable and the client fails with unsupported_transaction_version.",
        build_with(v1_offer(json!(["legacy"])), json!({})),
        reject(RejectCode::UnsupportedVersion, "unsupported_transaction_version: legacy is never built"),
    )
    .authored(None)
    .build();

    // ── sponsor: version admission ─────────────────────────────────────────
    x402_verify_v1_accept => verify(
        "x402-verify-v1-accept",
        BugType::Wire,
        sponsor_spec(),
        &[SPONSOR_SET, PAYLOAD_VERSION, V1_LAYOUT],
        "A sponsor accepting [0, 1] verifies the version-1 static layout (TransferChecked, Memo; computeUnitLimit 200000, priorityFee 1 lamport, maximum loadedAccountsDataSizeLimit in the header): accepted.",
        layout(MessageFormat::V1, Some(BOTH), None),
        Expect::Accept(Pin::Outcome),
    ).build();
    x402_verify_v1_not_accepted_reject => verify(
        "x402-verify-v1-not-accepted-reject",
        BugType::AuthBypass,
        sponsor_spec(),
        &[SPONSOR_SET, PAYLOAD_VERSION],
        "A sponsor with the default accepted set [0] receives the same valid version-1 transaction: rejected with unsupported_transaction_version before any instruction is inspected. Pair: x402-verify-v1-accept.",
        layout(MessageFormat::V1, None, None),
        reject(RejectCode::UnsupportedVersion, "unsupported_transaction_version"),
    ).build();
    x402_verify_v1_explicit_v0_sponsor_reject => verify(
        "x402-verify-v1-explicit-v0-sponsor-reject",
        BugType::AuthBypass,
        sponsor_spec(),
        &[SPONSOR_SET],
        "A sponsor configured with [0] explicitly receives a version-1 transaction.",
        layout(MessageFormat::V1, Some(&[0]), None),
        reject(RejectCode::UnsupportedVersion, "unsupported_transaction_version"),
    ).build();
    x402_verify_v0_with_v1_sponsor_accept => verify(
        "x402-verify-v0-with-v1-sponsor-accept",
        BugType::Wire,
        sponsor_spec(),
        &[SPONSOR_SET, PAYLOAD_VERSION],
        "A sponsor accepting [0, 1] still accepts the version-0 static layout, with extra.transactionVersions [0, 1] echoed in accepted.",
        layout(MessageFormat::V0, Some(BOTH), None),
        Expect::Accept(Pin::Outcome),
    ).build();

    // ── sponsor: version-1 size and compute budget ─────────────────────────
    x402_verify_v1_over_1232_accept => verify(
        "x402-verify-v1-over-1232-accept",
        BugType::Wire,
        size_spec(),
        &[SIZE_LIMITS, V1_LAYOUT],
        "Version-1 static layout whose Memo nonce is 1300 hex characters: about 1.6 KB serialized, over version 0's 1232 bytes but within version 1's 4096. Accepted.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::PadMemo { memo: 0, len: 1300 })),
        Expect::Accept(Pin::Outcome),
    ).build();
    x402_verify_v0_over_1232_reject => verify(
        "x402-verify-v0-over-1232-reject",
        BugType::Wire,
        size_spec(),
        &[SIZE_LIMITS],
        "The same 1300-character Memo in a version-0 static layout: over 1232 bytes, rejected whatever else the sponsor accepts. Pair: x402-verify-v1-over-1232-accept.",
        layout(MessageFormat::V0, Some(BOTH), Some(Mutation::PadMemo { memo: 0, len: 1300 })),
        reject(RejectCode::InvalidPayload, "a version-0 transaction over 1232 bytes"),
    )
    .authored(None)
    .build();
    x402_verify_v1_over_4096_reject => verify(
        "x402-verify-v1-over-4096-reject",
        BugType::Wire,
        size_spec(),
        &[SIZE_LIMITS],
        "Version-1 static layout with a 4000-character Memo: over the 4096-byte version-1 limit. Pair: x402-verify-v1-over-1232-accept.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::PadMemo { memo: 0, len: 4000 })),
        reject(RejectCode::InvalidPayload, "a version-1 transaction over 4096 bytes"),
    )
    .authored(None)
    .build();
    x402_verify_v1_compute_budget_instruction_reject => verify(
        "x402-verify-v1-compute-budget-instruction-reject",
        BugType::Settlement,
        spec(SVM, "2.2.1 Compute Budget Controls (SHOULD)", "A version-1 transaction that contains a Compute Budget instruction MUST be rejected."),
        &[V1_NO_BUDGET_IX, V1_BUDGET],
        "Version-1 static layout preceded by a SetComputeUnitLimit instruction: the runtime ignores it under version 1, so a sponsor bounding it bounds nothing. Pair: x402-verify-v1-accept.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::AddComputeBudget { data: LIMIT_IX })),
        from_table(&Mutation::AddComputeBudget { data: LIMIT_IX }),
    ).build();
    x402_verify_v1_missing_compute_unit_limit_reject => verify(
        "x402-verify-v1-missing-compute-unit-limit-reject",
        BugType::Settlement,
        caps_spec(),
        &[V1_CAPS, V1_BUDGET],
        "Version-1 header without computeUnitLimit (budgeted zero compute units; it cannot execute after the sponsor pays the fee). Pair: x402-verify-v1-accept.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::V1DropComputeUnitLimit)),
        from_table(&Mutation::V1DropComputeUnitLimit),
    ).build();
    x402_verify_v1_missing_loaded_data_limit_reject => verify(
        "x402-verify-v1-missing-loaded-data-limit-reject",
        BugType::Settlement,
        caps_spec(),
        &[V1_CAPS, V1_BUDGET],
        "Version-1 header without loadedAccountsDataSizeLimit (budgeted zero bytes; it fails at load time after the sponsor pays the fee). Pair: x402-verify-v1-accept.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::V1DropLoadedAccountsDataSizeLimit)),
        from_table(&Mutation::V1DropLoadedAccountsDataSizeLimit),
    )
    .authored(None)
    .build();
    x402_verify_v1_compute_limit_at_cap_accept => verify(
        "x402-verify-v1-compute-limit-at-cap-accept",
        BugType::Settlement,
        caps_spec(),
        &[V1_CAPS],
        "Version-1 header computeUnitLimit at the configured maximum (200000): accepted (the base layout already sits at the cap; this pins it explicitly next to its over-cap pair).",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::V1ComputeUnitLimit { limit: 200_000 })),
        Expect::Accept(Pin::Outcome),
    ).build();
    x402_verify_v1_compute_limit_over_cap_reject => verify(
        "x402-verify-v1-compute-limit-over-cap-reject",
        BugType::Settlement,
        caps_spec(),
        &[V1_CAPS],
        "Version-1 header computeUnitLimit 200001, one unit over the configured maximum.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::V1ComputeUnitLimit { limit: 200_001 })),
        from_table(&Mutation::V1ComputeUnitLimit { limit: 200_001 }),
    ).build();
    x402_verify_v1_priority_fee_at_cap_accept => verify(
        "x402-verify-v1-priority-fee-at-cap-accept",
        BugType::Settlement,
        spec(SVM, "3.1 Path 1 — Static Layout Verification (standard wallets)", "The legacy/version-0 Compute Budget price and the version-1 total priority fee MUST each be no greater than 5 lamports/CU on this path, using the normalization in §1.5 for version 1."),
        &[FAST_PATH_PRICE, V1_CAPS],
        "Version-1 priorityFee 1500 lamports over 300 units: exactly 5 lamports (5000000 micro-lamports) per unit, the fast-path cap, and under the 2000 lamport cap a sponsor may put on the total fee (scheme_exact_svm.md §2.2.1). Accepted (the cap is inclusive).",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::V1Budget { limit: 300, lamports: 1_500 })),
        Expect::Accept(Pin::Outcome),
    ).build();
    x402_verify_v1_priority_fee_over_cap_reject => verify(
        "x402-verify-v1-priority-fee-over-cap-reject",
        BugType::Settlement,
        spec(SVM, "3.1 Path 1 — Static Layout Verification (standard wallets)", "The legacy/version-0 Compute Budget price and the version-1 total priority fee MUST each be no greater than 5 lamports/CU on this path, using the normalization in §1.5 for version 1."),
        &[FAST_PATH_PRICE, V1_CAPS],
        "Version-1 priorityFee 1501 lamports over 300 units: one lamport above priorityFee * 1000000 <= 5000000 * 300, and still under a 2000 lamport cap on the total fee, so only the per-unit rule rejects it. A sponsor that compares the lamport total with the per-unit cap accepts it.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::V1Budget { limit: 300, lamports: 1_501 })),
        from_table(&Mutation::V1Budget { limit: 300, lamports: 1_501 }),
    ).build();
    x402_verify_v1_too_many_instructions_reject => verify(
        "x402-verify-v1-too-many-instructions-reject",
        BugType::Settlement,
        layout_spec(),
        &[V1_LAYOUT],
        "Version-1 layout with an instruction of a program outside the optional Lighthouse/Memo slots after the transfer. Pair: x402-verify-v1-accept.",
        layout(MessageFormat::V1, Some(BOTH), Some(Mutation::AddProgramInstruction { program: X402_OTHER_PAY_TO, data: &[1] })),
        from_table(&Mutation::AddProgramInstruction { program: X402_OTHER_PAY_TO, data: &[1] }),
    ).build();

    // ── sponsor: the same policy on version 1 ──────────────────────────────
    x402_verify_v1_underpay_reject => v1_policy(
        "x402-verify-v1-underpay-reject",
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "A matching transfer MAY exceed PaymentRequirements.amount (overpayment is tolerated to accommodate smart wallets with internal fee rounding); it MUST NOT be less."),
        &[NOT_LESS],
        "Version-1 TransferChecked one base unit short.",
        Mutation::BumpAmount { transfer: 0, delta: -1 },
    ).build();
    x402_verify_v1_wrong_recipient_reject => v1_policy(
        "x402-verify-v1-wrong-recipient-reject",
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "Across all top-level instructions and the full CPI trace, exactly one transfer MUST match the requirements (correct mint, correct destination ATA, amount >= required)."),
        &[EXACTLY_ONE, TRANSFER_MATCH],
        "Version-1 TransferChecked to another owner's ATA.",
        Mutation::SwapRecipient { transfer: 0, owner: X402_OTHER_PAY_TO },
    ).build();
    x402_verify_v1_wrong_mint_reject => v1_policy(
        "x402-verify-v1-wrong-mint-reject",
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "Across all top-level instructions and the full CPI trace, exactly one transfer MUST match the requirements (correct mint, correct destination ATA, amount >= required)."),
        &[EXACTLY_ONE, TRANSFER_MATCH],
        "Version-1 TransferChecked of another mint.",
        Mutation::WrongMint { transfer: 0, mint: OTHER_MINT, source_owner: CLIENT, destination_owner: X402_PAY_TO },
    ).build();
    x402_verify_v1_decimals_reject => v1_policy(
        "x402-verify-v1-decimals-reject",
        spec(SVM, "1.4 Exactly One Matching Transfer (MUST)", "Across all top-level instructions and the full CPI trace, exactly one transfer MUST match the requirements (correct mint, correct destination ATA, amount >= required)."),
        &[EXACTLY_ONE],
        "Version-1 TransferChecked declaring 9 decimals for a 6-decimal mint.",
        Mutation::SetDecimals { transfer: 0, decimals: 9 },
    ).build();
    x402_verify_v1_fee_payer_authority_reject => v1_policy(
        "x402-verify-v1-fee-payer-authority-reject",
        spec(SVM, "2.1.1 Fee Payer Isolation (MUST)", "The fee payer / sponsor MUST NOT be the authority on any observed transfer (self-spend protection)."),
        &[SELF_SPEND],
        "Version-1 TransferChecked whose authority is the sponsor.",
        Mutation::FeePayerAsAuthority { transfer: 0 },
    ).build();
    x402_verify_v1_fee_payer_in_accounts_reject => v1_policy(
        "x402-verify-v1-fee-payer-in-accounts-reject",
        spec(SVM, "3.2 Path 2 — Simulation-Based Smart Wallet Verification", "Fee payer isolation (§2.1.1): the fee payer MUST NOT appear in any instruction's accounts or as a program ID, after ALT resolution (§2.1.2)."),
        &[FEE_PAYER_ISOLATION],
        "Version-1 Memo instruction listing the sponsor as an account.",
        Mutation::FeePayerAsAccount { memo: 0 },
    ).build();
    x402_verify_v1_extra_signer_reject => v1_policy(
        "x402-verify-v1-extra-signer-reject",
        spec(SVM, "2.1.4 Signer Set Integrity (MUST)", "The transaction MUST NOT require any signatures beyond the client and the sponsor (feePayer)."),
        &["X402TX-9b240d95a0"],
        "Version-1 Memo instruction requiring a third signer (signed).",
        Mutation::ExtraSigner { memo: 0, seed: [21; 32] },
    ).build();
}
