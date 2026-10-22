//! MPP charge (Solana) cases: client builds against the fixture RPC, and
//! server verifies of kit-built transactions, valid or mutated.
//!
//! Every verify vector pins `input.transaction` (built by the kit's client
//! builder, then optionally mutated), so server-only SDKs verify the same
//! bytes instead of building their own.

use serde_json::{json, Value};

use super::{client_secret, mints};
use crate::case::{
    spec, BugType, Case, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef,
    Suite,
};
use crate::keys::{
    BLOCKHASH, CHARGE_RECIPIENT, CLIENT, MINT, MINT_2022, OTHER_MINT, SPLIT_RECIPIENT,
    SPLIT_RECIPIENT_2, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM,
};
use crate::mutate::Mutation;

pub(super) const CHARGE: &str = "mpp-specs/specs/methods/solana/draft-solana-charge-00.md";

const DECIMALS_PRESENT: &str = "MPP-5348f3f797";
const TOKEN_PROGRAM_FETCH: &str = "MPP-7743ae4e51";
const TOKEN_PROGRAM_REJECT: &str = "MPP-c189ef935e";
const SOL_CONSTRUCTION: &str = "MPP-e02293d02d";
const SPLIT_ATA_CLIENT_PAYS: &str = "MPP-197d674f50";
const SPLIT_ATA_CONSTRUCTION: &str = "MPP-64da85f4f3";
pub(super) const ONLY_EXPECTED_INSTRUCTIONS: &str = "MPP-048617f9d7";
pub(super) const UNEXPECTED_REJECTED: &str = "MPP-1a2e7c737e";
pub(super) const SPL_LEG_MISSING: &str = "MPP-96ba338b1e";
pub(super) const SOL_LEG_MISSING: &str = "MPP-6e9ac6c31d";
pub(super) const REMAINDER_POSITIVE: &str = "MPP-b134044e08";
const DUPLICATE_LEGS_SEPARATE: &str = "MPP-6ce505e77b";
const SOL_ONE_INSTRUCTION_ONE_LEG: &str = "MPP-4a77950278";
const SPL_ONE_INSTRUCTION_ONE_LEG: &str = "MPP-d90a2b66e5";

fn decimals_spec() -> SpecRef {
    spec(
        CHARGE,
        "Method Details",
        "MUST be present when currency is a mint address; MUST be absent when currency is \"sol\".",
    )
}

fn token_program_fetch_spec() -> SpecRef {
    spec(
        CHARGE,
        "Method Details",
        "If omitted, clients MUST determine the correct token program by fetching the mint account from the network and inspecting its owner program.",
    )
}

fn token_program_reject_spec() -> SpecRef {
    spec(
        CHARGE,
        "Method Details",
        "If that lookup fails, returns an unexpected owner, or cannot be verified, clients MUST reject the challenge rather than falling back to the Token Program.",
    )
}

fn spl_leg_spec() -> SpecRef {
    spec(
        CHARGE,
        "SPL Token Verification",
        "Verify that at least one matching transferChecked instruction uses that derived ATA as destination and has tokenAmount.amount equal to the primary payment amount.",
    )
}

fn instructions_spec() -> SpecRef {
    spec(
        CHARGE,
        "Transaction Payload Security",
        "Servers MUST verify that the transaction contains only the expected instructions: transfer instruction(s) matching the challenge parameters, ATA creation (idempotent), and optionally compute budget instructions.",
    )
}

/// An SPL charge request with `methodDetails` merged over the defaults
/// (localnet, Token Program, decimals 6, the fixed blockhash).
pub(super) fn spl_request(amount: &str, details: Value) -> Value {
    let mut md = json!({
        "network": "localnet",
        "decimals": 6,
        "tokenProgram": TOKEN_PROGRAM,
        "recentBlockhash": BLOCKHASH,
    });
    if let Value::Object(details) = details {
        for (k, v) in details {
            if v.is_null() {
                md.as_object_mut().unwrap().remove(&k);
            } else {
                md[k] = v;
            }
        }
    }
    json!({ "amount": amount, "currency": MINT, "recipient": CHARGE_RECIPIENT, "methodDetails": md })
}

pub(super) fn sol_request(amount: &str, details: Value) -> Value {
    let mut md = json!({ "network": "localnet", "recentBlockhash": BLOCKHASH });
    if let Value::Object(details) = details {
        for (k, v) in details {
            md[k] = v;
        }
    }
    json!({ "amount": amount, "currency": "sol", "recipient": CHARGE_RECIPIENT, "methodDetails": md })
}

pub(super) fn input(request: Value) -> Value {
    json!({ "signerSecretKey": client_secret(), "request": request })
}

pub(super) fn input_with_mints(request: Value, entries: &[(&str, &str, u8)]) -> Value {
    let mut input = input(request);
    input["rpcFixtures"] = json!({ "mints": mints(entries) });
    input
}

pub(super) fn shape(transfers: bool, memo: bool, limit: bool, forbidden: &[&'static str]) -> Pin {
    Pin::TransactionShape {
        fee_payer: true,
        transfers,
        memo,
        max_compute_unit_limit: limit,
        forbidden_programs: forbidden.to_vec(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_case(
    id: &str,
    file: &'static str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    input: Value,
    expect: Expect,
) -> Case {
    CaseBuilder::new(
        id,
        file,
        Suite::Charge,
        Intent::Charge,
        Mode::BuildTransaction,
        Role::Client,
        bug,
        spec,
        description,
        Input::Static(input),
        expect,
    )
    .requirements(reqs)
    .build()
}

/// A verify case whose pinned transaction the kit builds from `input`,
/// optionally mutated. A mutated case's reject code comes from the operator
/// table, never from the case.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_case(
    id: &str,
    file: &'static str,
    bug: BugType,
    spec: SpecRef,
    reqs: &[&str],
    description: &str,
    base: Value,
    mutation: Option<Mutation>,
    accept: Pin,
    reason: Option<&str>,
) -> CaseBuilder {
    let expect = match &mutation {
        Some(m) => Expect::Reject {
            code: m
                .expected(Suite::Charge)
                .unwrap_or_else(|| panic!("{id}: {m:?} has no charge reject code")),
            reason: reason.map(str::to_string),
        },
        None => Expect::Accept(accept),
    };
    let description = match &mutation {
        Some(m) => format!("{description} Mutation: {}.", m.describe()),
        None => description.to_string(),
    };
    CaseBuilder::new(
        id,
        file,
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
            built_from: None,
        },
        expect,
    )
    .requirements(reqs)
}

pub(super) fn reject(code: RejectCode, reason: &str) -> Expect {
    Expect::Reject {
        code,
        reason: Some(reason.to_string()),
    }
}

fn duplicate_splits(sol: bool) -> Value {
    let splits = json!([
        { "recipient": SPLIT_RECIPIENT, "amount": "100", "memo": "leg 1" },
        { "recipient": SPLIT_RECIPIENT, "amount": "100", "memo": "leg 2" }
    ]);
    if sol {
        input(sol_request("1000", json!({ "splits": splits })))
    } else {
        input(spl_request("1000", json!({ "splits": splits })))
    }
}

fn duplicate_memos() -> Value {
    input(spl_request(
        "1000",
        json!({ "splits": [
            { "recipient": SPLIT_RECIPIENT, "amount": "100", "memo": "platform fee" },
            { "recipient": SPLIT_RECIPIENT_2, "amount": "100", "memo": "platform fee" }
        ] }),
    ))
}

crate::registry! {
    charge_spl_missing_decimals_reject => build_case(
        "charge-spl-missing-decimals-reject",
        "charge-defaults.json",
        BugType::Defaults,
        decimals_spec(),
        &[DECIMALS_PRESENT],
        "draft-solana-charge-00 methodDetails: decimals \"MUST be present when currency is a mint address\". A client must refuse the challenge rather than assume a value.",
        input_with_mints(spl_request("1000", json!({ "decimals": null })), &[(MINT, TOKEN_PROGRAM, 6)]),
        reject(RejectCode::InvalidChallenge, "decimals missing for a mint currency"),
    );
    charge_spl_token_program_from_mint_owner => build_case(
        "charge-spl-token-program-from-mint-owner",
        "charge-defaults.json",
        BugType::Defaults,
        token_program_fetch_spec(),
        &[TOKEN_PROGRAM_FETCH],
        "draft-solana-charge-00 methodDetails: tokenProgram omitted, so the client MUST fetch the mint account and use its owner (here the SPL Token program).",
        input_with_mints(spl_request("1000", json!({ "tokenProgram": null })), &[(MINT, TOKEN_PROGRAM, 6)]),
        Expect::Accept(shape(true, false, true, &[])),
    );
    charge_token2022_program_from_mint_owner => build_case(
        "charge-token2022-program-from-mint-owner",
        "charge-defaults.json",
        BugType::Defaults,
        token_program_fetch_spec(),
        &[TOKEN_PROGRAM_FETCH],
        "draft-solana-charge-00 methodDetails: tokenProgram omitted for a Token-2022 mint; the client MUST resolve the program from the mint owner, not from a currency table.",
        input_with_mints(
            json!({
                "amount": "1000",
                "currency": MINT_2022,
                "recipient": CHARGE_RECIPIENT,
                "methodDetails": { "network": "mainnet", "recentBlockhash": BLOCKHASH, "decimals": 6 }
            }),
            &[(MINT_2022, TOKEN_2022_PROGRAM, 6)],
        ),
        Expect::Accept(shape(true, false, false, &[])),
    );
    charge_token_program_lookup_missing_mint_reject => build_case(
        "charge-token-program-lookup-missing-mint-reject",
        "charge-defaults.json",
        BugType::Defaults,
        token_program_reject_spec(),
        &[TOKEN_PROGRAM_REJECT],
        "draft-solana-charge-00 methodDetails: tokenProgram omitted and the mint account does not exist; \"clients MUST reject the challenge rather than falling back to the Token Program\".",
        input_with_mints(spl_request("1000", json!({ "tokenProgram": null })), &[]),
        reject(RejectCode::InvalidChallenge, "mint lookup failed"),
    );
    charge_token_program_unexpected_owner_reject => build_case(
        "charge-token-program-unexpected-owner-reject",
        "charge-defaults.json",
        BugType::Defaults,
        token_program_reject_spec(),
        &[TOKEN_PROGRAM_REJECT],
        "draft-solana-charge-00 methodDetails: tokenProgram omitted and the mint account is owned by neither token program; the client MUST reject.",
        input_with_mints(spl_request("1000", json!({ "tokenProgram": null })), &[(MINT, SYSTEM_PROGRAM, 6)]),
        reject(RejectCode::InvalidChallenge, "unexpected mint owner"),
    );
    charge_sol_native_build => build_case(
        "charge-sol-native-build",
        "charge-defaults.json",
        BugType::Wire,
        spec(
            CHARGE,
            "Client Transaction Construction",
            "The client MUST construct a transaction containing a System Program transfer instruction with:",
        ),
        &[SOL_CONSTRUCTION],
        "Native SOL charge: currency \"sol\" must produce a System Program transfer of lamports, no SPL token program and no ATA creation.",
        input(sol_request("1000000", json!({}))),
        Expect::Accept(shape(true, false, false, &[TOKEN_PROGRAM, TOKEN_2022_PROGRAM])),
    );
    charge_split_ata_memo_envelope_accept => verify_case(
        "charge-split-ata-memo-envelope-accept",
        "charge-envelope.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "Split Recipient ATA Creation",
            "When the client is the transaction fee payer (feePayer is false or omitted), clients MAY include ATA creation instructions only for split recipients, and MUST include one for each split whose entry sets ataCreationRequired: true.",
        ),
        &[SPLIT_ATA_CLIENT_PAYS, SPLIT_ATA_CONSTRUCTION],
        "Full charge envelope accept: primary transfer plus a split with idempotent ATA creation and a memo. Exercises the complete decoded envelope shape (transfers, ATA-create allowlist, memo) the verifier must accept. The pinned transaction is the Rust kit's build (RULINGS C5: the client includes the split ATA creation).",
        input(spl_request("1000", json!({ "splits": [{
            "recipient": SPLIT_RECIPIENT,
            "amount": "250",
            "ataCreationRequired": true,
            "memo": "conformance split"
        }] }))),
        None,
        shape(true, true, false, &[]),
        None,
    )
    .build();
    charge_compute_price_over_cap_reject => verify_case(
        "charge-compute-price-over-cap-reject",
        "charge-rejects.json",
        BugType::Settlement,
        instructions_spec(),
        &[ONLY_EXPECTED_INSTRUCTIONS],
        "Divergence class: compute-unit-price cap. A transaction whose compute unit price exceeds 5_000_000 micro-lamports must be rejected by the verifier (sponsor cost control; the cap is pay-kit policy, the spec only requires that instructions are the expected ones). The pinned transaction is the kit's build, mutated.",
        input(spl_request("1000", json!({}))),
        Some(Mutation::SetComputeUnitPrice { micro_lamports: 5_000_001 }),
        Pin::Outcome,
        Some("compute unit price exceeds the 5_000_000 micro-lamport cap"),
    )
    .build();
    charge_feepayer_as_authority_reject => CaseBuilder::new(
        "charge-feepayer-as-authority-reject",
        "charge-rejects.json",
        Suite::Charge,
        Intent::Charge,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::AuthBypass,
        spec(
            CHARGE,
            "Transaction Payload Security",
            "A malicious client could craft a transaction that transfers funds FROM the server's fee payer account rather than simply paying fees.",
        ),
        "Divergence class: fee-payer-as-authority. When the fee payer signs as the transfer authority, the verifier must reject so a server fee payer cannot also be drained as the funding source. The challenge names the client itself as feePayerKey; the pinned transaction is the kit's client-paid build of the same charge (fee payer = authority = client), because the kit's client refuses to build a sponsored charge whose sponsor is the signer.",
        Input::ChargeTransaction {
            base: input(spl_request("1000", json!({ "feePayer": true, "feePayerKey": CLIENT }))),
            mutation: None,
            built_from: Some(input(spl_request("1000", json!({})))),
        },
        reject(
            RejectCode::FeePayerNotAuthority,
            "fee payer cannot authorize the SPL payment transfer (fee-payer == authority == source)",
        ),
    )
    .requirements(&[ONLY_EXPECTED_INSTRUCTIONS])
    .build();
    charge_transferchecked_decimals_mismatch_reject => verify_case(
        "charge-transferchecked-decimals-mismatch-reject",
        "charge-rejects.json",
        BugType::Malleability,
        spl_leg_spec(),
        &[SPL_LEG_MISSING],
        "Divergence class: transferChecked decimals mismatch. The transaction encodes decimals=9 in transferChecked but the challenge pins decimals=6; the verifier must reject.",
        input(spl_request("1000", json!({}))),
        Some(Mutation::SetDecimals { transfer: 0, decimals: 9 }),
        Pin::Outcome,
        Some("decimals=9 transfer fails the decimals=6 match key, surfacing as a no-matching-transfer reject; isolating the decimals field itself is the job of a positive-control vector pair, not this reason check"),
    )
    .build();
    charge_transferchecked_decimals_match_accept => verify_case(
        "charge-transferchecked-decimals-match-accept",
        "charge-rejects.json",
        BugType::Malleability,
        spl_leg_spec(),
        &[SPL_LEG_MISSING],
        "Positive control for charge-transferchecked-decimals-mismatch-reject and the wrong-amount / wrong-recipient / wrong-mint rejects: the same request with the kit's unmutated build (decimals=6), which the verifier must accept.",
        input(spl_request("1000", json!({}))),
        None,
        shape(true, false, false, &[]),
        None,
    )
    .build();
    charge_splits_consume_amount_reject => build_case(
        "charge-splits-consume-amount-reject",
        "charge-rejects.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "Method Details",
            "The primary recipient receives amount minus the sum of all split amounts; this remainder MUST be greater than zero.",
        ),
        &[REMAINDER_POSITIVE],
        "Divergence class: splits consume the entire amount. A single split equal to the total amount leaves the primary recipient zero; the build path must reject because the primary amount must be strictly positive.",
        input(spl_request("1000", json!({ "splits": [{ "recipient": SPLIT_RECIPIENT, "amount": "1000" }] }))),
        reject(RejectCode::SplitsExceedAmount, "splits consume the entire amount; primary recipient must receive a positive amount"),
    );
    charge_verify_wrong_amount_reject => verify_case(
        "charge-verify-wrong-amount-reject",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spl_leg_spec(),
        &[SPL_LEG_MISSING],
        "SPL charge verify: the primary transfer pays one base unit less than the challenge amount.",
        input(spl_request("1000", json!({}))),
        Some(Mutation::BumpAmount { transfer: 0, delta: -1 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_wrong_recipient_reject => verify_case(
        "charge-verify-wrong-recipient-reject",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spl_leg_spec(),
        &[SPL_LEG_MISSING],
        "SPL charge verify: the primary transfer lands in another owner's ATA.",
        input(spl_request("1000", json!({}))),
        Some(Mutation::SwapRecipient { transfer: 0, owner: SPLIT_RECIPIENT_2 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_verify_wrong_mint_reject => verify_case(
        "charge-verify-wrong-mint-reject",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spl_leg_spec(),
        &[SPL_LEG_MISSING],
        "SPL charge verify: the primary transfer pays the right owner in another mint.",
        input(spl_request("1000", json!({}))),
        Some(Mutation::WrongMint {
            transfer: 0,
            mint: OTHER_MINT,
            source_owner: CLIENT,
            destination_owner: CHARGE_RECIPIENT,
        }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_split_duplicate_recipient_sol_accept => verify_case(
        "charge-split-duplicate-recipient-sol-accept",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "Native SOL Verification",
            "A single transfer instruction MUST NOT satisfy more than one required payment leg, even if multiple legs share the same recipient.",
        ),
        &[SOL_ONE_INSTRUCTION_ONE_LEG, DUPLICATE_LEGS_SEPARATE],
        "Positive control: two SOL splits to the same recipient, each paid by its own System transfer.",
        duplicate_splits(true),
        None,
        shape(true, false, false, &[]),
        None,
    )
    .build();
    charge_split_duplicate_recipient_sol_reuse_reject => verify_case(
        "charge-split-duplicate-recipient-sol-reuse-reject",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "Native SOL Verification",
            "A single transfer instruction MUST NOT satisfy more than one required payment leg, even if multiple legs share the same recipient.",
        ),
        &[SOL_ONE_INSTRUCTION_ONE_LEG, SOL_LEG_MISSING],
        "Two SOL splits to the same recipient, but only one split transfer is present, so one instruction would have to satisfy both legs.",
        duplicate_splits(true),
        Some(Mutation::DuplicateLegReuse { transfer: 2 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_split_duplicate_recipient_spl_accept => verify_case(
        "charge-split-duplicate-recipient-spl-accept",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "SPL Token Verification",
            "A single instruction MUST NOT satisfy more than one required payment leg, even if multiple legs resolve to the same destination ATA.",
        ),
        &[SPL_ONE_INSTRUCTION_ONE_LEG, DUPLICATE_LEGS_SEPARATE],
        "Positive control: two SPL splits to the same recipient, each paid by its own transferChecked.",
        duplicate_splits(false),
        None,
        shape(true, false, false, &[]),
        None,
    )
    .build();
    charge_split_duplicate_recipient_spl_reuse_reject => verify_case(
        "charge-split-duplicate-recipient-spl-reuse-reject",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "SPL Token Verification",
            "A single instruction MUST NOT satisfy more than one required payment leg, even if multiple legs resolve to the same destination ATA.",
        ),
        &[SPL_ONE_INSTRUCTION_ONE_LEG, SPL_LEG_MISSING],
        "Two SPL splits to the same recipient, but only one split transferChecked is present, so one instruction would have to satisfy both legs.",
        duplicate_splits(false),
        Some(Mutation::DuplicateLegReuse { transfer: 2 }),
        Pin::Outcome,
        None,
    )
    .build();
    charge_split_duplicate_memo_accept => verify_case(
        "charge-split-duplicate-memo-accept",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "Method Details",
            "If the same recipient appears more than once in splits, each occurrence is a distinct payment leg and MUST be verified separately; servers MUST NOT implicitly aggregate such entries.",
        ),
        &[DUPLICATE_LEGS_SEPARATE],
        "Positive control: two splits with the same memo text, each carried by its own Memo instruction.",
        duplicate_memos(),
        None,
        shape(true, true, false, &[]),
        None,
    )
    .build();
    charge_split_duplicate_memo_reuse_reject => verify_case(
        "charge-split-duplicate-memo-reuse-reject",
        "charge-verify-mutations.json",
        BugType::Settlement,
        spec(
            CHARGE,
            "Method Details",
            "If the same recipient appears more than once in splits, each occurrence is a distinct payment leg and MUST be verified separately; servers MUST NOT implicitly aggregate such entries.",
        ),
        &[DUPLICATE_LEGS_SEPARATE, UNEXPECTED_REJECTED],
        "Two splits with the same memo text but a single Memo instruction: one memo must not satisfy two legs. The spec does not require split memos on-chain; this pins the Rust kit's per-leg memo check.",
        duplicate_memos(),
        Some(Mutation::DropMemo { memo: 1 }),
        Pin::Outcome,
        None,
    )
    .build();
}
